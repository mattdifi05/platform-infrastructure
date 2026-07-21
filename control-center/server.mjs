import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { AsyncLocalStorage } from "node:async_hooks";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, statfsSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AuthRequestError, createControlCenterAuth } from "./auth/oidc.mjs";
import { resolveAuthorizationCapability } from "./auth/route-capabilities.mjs";
import { controlCenterScriptTags, controlCenterStylesheetLinks, controlCenterUiContract } from "./components/ui/controlCenterUi.mjs";
import {
  activatePrincipalBinding,
  assertManagedDatabaseName,
  assertPrincipalCleanupAllowed,
  assertPrincipalCreateAllowed,
  assertPrincipalDeletionAllowed,
  assertPrincipalRotationAllowed,
  createPrincipalBinding,
  DatabaseOwnershipError,
  generatedDatabasePrincipal,
  principalBindingFor,
  reservePrincipalBinding,
} from "./database/ownership.mjs";
import {
  createDatabaseDeleteOperation,
  databaseDeleteConfirmation,
  findDatabaseDeleteRestorePoint,
  parseDatabaseDeleteOperation,
  transitionDatabaseDeleteOperation,
} from "./database/destructive-workflow.mjs";
import {
  backupDocumentDigest,
  backupResourceId,
  createBackupJobDocument,
  parseBackupJobDocument,
  parseBackupManifestDocument,
} from "./backup/contracts.mjs";
import { safeBackupPreview } from "./backup/preview.mjs";
import {
  loadVaultKeyring,
  openLegacyVaultCiphertext,
  openVaultCiphertext,
  readLegacyVaultMaterial,
  sealVaultPlaintext,
} from "./vault/keyring.mjs";
import { controlIcon } from "./components/ui/controlIcons.mjs";
import { createControlStateStore, validateStateRecord } from "./state/catalog.mjs";
import { executeStatusChecks } from "./status/executor.mjs";
import {
  createStatusEventBroker,
  pumpStatusEventStream,
  StatusEventStreamError,
} from "./status/event-stream.mjs";
import { createProjectDiskUsageReader, unavailableUsage as unavailableProjectDiskUsage } from "./resources/project-disk-usage.mjs";

const port = Number(process.env.CONTROL_CENTER_PORT || 8080);
const bindHost = String(process.env.CONTROL_CENTER_BIND_HOST || "0.0.0.0").trim();
const appRoot = path.dirname(fileURLToPath(import.meta.url));
const controlCenterStylesRoot = process.env.CONTROL_CENTER_STYLES_ROOT || path.join(appRoot, "styles");
const publicRoot = process.env.CONTROL_CENTER_PUBLIC_ROOT || path.join(appRoot, "public");
const projectsRoot = process.env.PROJECTS_ROOT || "/var/www/projects";
const docsRoot = process.env.CONTROL_CENTER_DOCS_ROOT || "/var/www/infra-docs";
const platformInfraRoot = process.env.CONTROL_CENTER_INFRA_ROOT || process.env.PLATFORM_INFRA_ROOT || docsRoot;
const backupRoot = process.env.CONTROL_CENTER_BACKUP_ROOT || path.join(platformInfraRoot, "backups");
const databasesFile = process.env.PROJECT_DATABASES_FILE || "/var/www/project-state/databases.json";
const databasePrincipalsFile = process.env.PROJECT_DATABASE_PRINCIPALS_FILE || "/var/www/project-state/database-principals.json";
const databaseDeleteOperationsFile = process.env.PROJECT_DATABASE_DESTRUCTIVE_OPERATIONS_FILE || "/var/www/project-state/database-destructive-operations.json";
const databaseCredentialDir = process.env.PROJECT_DATABASE_CREDENTIAL_DIR || path.join(path.dirname(databasesFile), "database-credentials");
const vaultFile = process.env.PROJECT_VAULT_FILE || "/var/www/project-state/secret-vault.json";
const vaultKeyFile = process.env.CONTROL_CENTER_VAULT_KEY_FILE || "";
const vaultActiveKeyId = process.env.CONTROL_CENTER_VAULT_ACTIVE_KEY_ID || "";
const vaultLegacyKeyFile = process.env.CONTROL_CENTER_VAULT_LEGACY_KEY_FILE || "";
const existingSecretsDir = process.env.CONTROL_CENTER_EXISTING_SECRETS_DIR || path.join(platformInfraRoot, "secrets");
const includeRunSecretsInVaultImport = parseBoolean(process.env.CONTROL_CENTER_IMPORT_RUN_SECRETS || "");
const vaultRevealTtlMs = clampNumber(Number(process.env.CONTROL_CENTER_VAULT_REVEAL_TTL_MS || 120000), 10000, 600000);
const backupJobsDir = process.env.PROJECT_BACKUP_JOBS_DIR || "/var/www/project-state/backup-jobs";
const dockerStatsFile = process.env.PROJECT_DOCKER_STATS_FILE || "/var/www/project-state/docker-stats.json";
const reportsRoot = process.env.CONTROL_CENTER_REPORTS_ROOT || path.join(platformInfraRoot, "reports");
const databaseDeleteEvidenceMaxAgeMs = clampNumber(Number(process.env.CONTROL_CENTER_DATABASE_DELETE_EVIDENCE_MAX_AGE_SECONDS || 86400), 3600, 604800) * 1000;
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
const dockerStatsMaxAgeMs = clampNumber(Number(process.env.CONTROL_CENTER_DOCKER_STATS_MAX_AGE_SECONDS || 15) * 1000, 5000, 120000);
const resourceMetricsCache = { value: null, expiresAt: 0, failedUntil: 0 };
const projectDiskUsageReader = createProjectDiskUsageReader({
  ttlMs: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_TTL_MS || 30000), 1000, 300000),
  partialTtlMs: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_PARTIAL_TTL_MS || 5000), 1000, 30000),
  staleTtlMs: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_STALE_TTL_MS || 300000), 30000, 3600000),
  maxConcurrency: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_CONCURRENCY || 2), 1, 8),
  scanOptions: {
    maxDepth: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_MAX_DEPTH || 32), 1, 128),
    maxNodes: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_MAX_NODES || 50000), 100, 1000000),
    maxBytes: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_MAX_BYTES || 100 * 1024 * 1024 * 1024), 1024 * 1024, Number.MAX_SAFE_INTEGER),
    timeoutMs: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_TIMEOUT_MS || 1500), 50, 10000),
    yieldEvery: clampNumber(Number(process.env.CONTROL_CENTER_PROJECT_DISK_USAGE_YIELD_EVERY || 64), 1, 1000),
  },
});
const controlContextCacheTtlMs = clampNumber(Number(process.env.CONTROL_CENTER_CONTEXT_CACHE_TTL_MS || 2000), 250, 5000);
const controlContextCache = { key: "", value: null, expiresAt: 0, pending: null };
const phpMyAdminInternalUrl = String(process.env.CONTROL_CENTER_PHPMYADMIN_INTERNAL_URL || "http://phpmyadmin:80").replace(/\/$/, "");
const phpPgAdminInternalUrl = String(process.env.CONTROL_CENTER_PHPPGADMIN_INTERNAL_URL || "http://phppgadmin:80").replace(/\/$/, "");
const databaseLiveApply = parseBoolean(process.env.CONTROL_CENTER_DATABASE_LIVE_APPLY || "");
const mariadbHost = normalizeHost(process.env.CONTROL_CENTER_MARIADB_HOST || "mariadb");
const mariadbPort = clampNumber(Number(process.env.CONTROL_CENTER_MARIADB_PORT || 3306), 1, 65535);
const mariadbRootUser = sanitizeDatabasePrincipal(process.env.CONTROL_CENTER_MARIADB_ROOT_USER || "root") || "root";
const mariadbRootPasswordFile = process.env.CONTROL_CENTER_MARIADB_ROOT_PASSWORD_FILE || "";
const postgresHost = normalizeHost(process.env.CONTROL_CENTER_POSTGRES_HOST || "postgres");
const postgresPort = clampNumber(Number(process.env.CONTROL_CENTER_POSTGRES_PORT || 5432), 1, 65535);
const postgresSuperuser = sanitizeDatabasePrincipal(process.env.CONTROL_CENTER_POSTGRES_SUPERUSER || "postgres") || "postgres";
const postgresSuperuserPasswordFile = process.env.CONTROL_CENTER_POSTGRES_SUPERUSER_PASSWORD_FILE || "";
const statusWafUrl = String(process.env.CONTROL_CENTER_STATUS_WAF_URL || "https://waf:8443").replace(/\/$/, "");
const statusProbeTimeoutMs = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_PROBE_TIMEOUT_MS || 4000), 500, 15000);
const statusProbeTlsVerify = parseBoolean(process.env.CONTROL_CENTER_STATUS_TLS_VERIFY || "");
const statusRunStepDelayMs = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STEP_DELAY_MS || 1500), 0, 10000);
const statusRunCheckTimeoutMs = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_CHECK_TIMEOUT_MS || 30000), 1000, 300000);
const statusEventTailMaxRecords = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_EVENT_TAIL_MAX_RECORDS || 2000), 100, 10000);
const statusEventTailMaxBytes = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_EVENT_TAIL_MAX_BYTES || 16 * 1024 * 1024), 64 * 1024, 64 * 1024 * 1024);
const statusEventMaxRecordBytes = Math.min(
  statusEventTailMaxBytes,
  clampNumber(Number(process.env.CONTROL_CENTER_STATUS_EVENT_MAX_RECORD_BYTES || 256 * 1024), 1024, 4 * 1024 * 1024),
);
const statusEventRetentionMaxRecords = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_EVENT_RETENTION_MAX_RECORDS || 5000), 100, 100000);
const statusEventRetentionMaxBytes = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_EVENT_RETENTION_MAX_BYTES || 8 * 1024 * 1024), 64 * 1024, 64 * 1024 * 1024);
const statusEventRetentionMaxRecordBytes = Math.min(
  statusEventRetentionMaxBytes,
  clampNumber(Number(process.env.CONTROL_CENTER_STATUS_EVENT_RETENTION_MAX_RECORD_BYTES || 256 * 1024), 1024, 4 * 1024 * 1024),
);
const statusStreamMaxSubscribers = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_MAX_SUBSCRIBERS || 64), 1, 4096);
const statusStreamMaxSubscribersPerPrincipal = Math.min(
  statusStreamMaxSubscribers,
  clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_MAX_PER_PRINCIPAL || 4), 1, 256),
);
const statusStreamMaxSubscribersPerRun = Math.min(
  statusStreamMaxSubscribers,
  clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_MAX_PER_RUN || 16), 1, 1024),
);
const statusStreamHeartbeatMs = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_HEARTBEAT_MS || 15000), 100, 300000);
const statusStreamMaxDurationMs = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_MAX_DURATION_MS || 6 * 60 * 1000), 1000, 24 * 60 * 60 * 1000);
const statusStreamBackpressureTimeoutMs = clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_BACKPRESSURE_TIMEOUT_MS || 5000), 100, 60000);
const statusEventBroker = createStatusEventBroker({
  maxSubscribers: statusStreamMaxSubscribers,
  maxSubscribersPerPrincipal: statusStreamMaxSubscribersPerPrincipal,
  maxSubscribersPerRun: statusStreamMaxSubscribersPerRun,
  maxQueueEvents: clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_QUEUE_EVENTS || 128), 1, 10000),
  maxQueueBytes: clampNumber(Number(process.env.CONTROL_CENTER_STATUS_STREAM_QUEUE_BYTES || 1024 * 1024), 1024, 64 * 1024 * 1024),
});
const controlState = createControlStateStore(process.env);
const controlAuth = await createControlCenterAuth();
const requestIdentity = new AsyncLocalStorage();

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

    if (url.pathname === "/auth/login" && req.method === "GET") {
      const location = await controlAuth.beginLogin(req);
      redirect(res, location);
      return;
    }

    if (url.pathname === "/auth/callback" && req.method === "GET") {
      try {
        const login = await controlAuth.completeLogin(url);
        appendAudit({
          action: "admin.oidc.login.success",
          actor: login.subject,
          target: login.subject,
          environment,
          risk: "low",
          result: "success",
          dryRun: false,
          summary: `Passkey-backed OIDC session created with ${login.role} authorization.`,
        });
        res.setHeader("set-cookie", login.cookies);
        redirect(res, "/");
      } catch (error) {
        appendAudit({
          action: "admin.oidc.login.failed",
          target: "control-center",
          environment,
          risk: "medium",
          result: "failed",
          dryRun: false,
          summary: "OIDC login rejected without creating an administrative session.",
        });
        const status = error instanceof AuthRequestError ? error.status : 401;
        html(res, renderLogin("Autenticazione passkey non riuscita."), status);
      }
      return;
    }

    if (url.pathname === "/auth/provider-security-event" && req.method === "POST") {
      let result;
      try {
        result = await controlAuth.providerSecurityEvent(req);
      } catch (error) {
        const invalidToken = error instanceof AuthRequestError;
        try {
          appendAudit({
            action: invalidToken
              ? "admin.oidc.provider-security-event.rejected"
              : "admin.oidc.provider-security-event.failed",
            target: "control-center-sessions",
            environment,
            risk: "medium",
            result: "failed",
            dryRun: false,
            summary: invalidToken
              ? "Signed provider account or authorization event was rejected before session mutation."
              : "Provider security event processing failed or had an indeterminate commit outcome; an idempotent retry is required.",
          });
        } catch {
          // Preserve the protocol status even when the local audit sink is unavailable.
        }
        json(res, {
          error: invalidToken ? "oidc_provider_security_event_rejected" : "oidc_provider_security_event_unavailable",
          message: invalidToken
            ? "Provider security event was rejected."
            : "Provider security event processing is temporarily unavailable; retry safely.",
        }, invalidToken ? error.status : 503);
        return;
      }

      try {
        appendAudit({
          action: "admin.oidc.provider-security-event.accepted",
          target: "control-center-sessions",
          environment,
          risk: "medium",
          result: "success",
          dryRun: false,
          summary: `Validated provider security event processed; type=${result.eventType} revoked=${Number(result.revoked || 0)} replayed=${result.replayed === true}.`,
        });
      } catch {
        json(res, {
          error: "oidc_provider_security_event_audit_unavailable",
          message: "Provider security event was processed, but completion evidence is temporarily unavailable; retry safely.",
        }, 503);
        return;
      }
      json(res, { ok: true, replayed: result.replayed === true, revoked: Number(result.revoked || 0) });
      return;
    }

    if (url.pathname === "/auth/backchannel-logout" && req.method === "POST") {
      let result;
      try {
        result = await controlAuth.backchannelLogout(req);
      } catch (error) {
        const invalidToken = error instanceof AuthRequestError;
        try {
          appendAudit({
            action: invalidToken
              ? "admin.oidc.backchannel-logout.rejected"
              : "admin.oidc.backchannel-logout.failed",
            target: "control-center-sessions",
            environment,
            risk: "medium",
            result: "failed",
            dryRun: false,
            summary: invalidToken
              ? "OIDC back-channel logout signal was rejected before session mutation."
              : "OIDC back-channel logout processing failed or had an indeterminate commit outcome; an idempotent retry is required.",
          });
        } catch {
          // Preserve the protocol status even when the local audit sink is unavailable.
        }
        const status = invalidToken ? error.status : 503;
        json(res, {
          error: invalidToken ? "oidc_backchannel_logout_rejected" : "oidc_backchannel_logout_unavailable",
          message: invalidToken
            ? "OIDC back-channel logout was rejected."
            : "OIDC back-channel logout is temporarily unavailable; retry safely.",
        }, status);
        return;
      }

      try {
        appendAudit({
          action: "admin.oidc.backchannel-logout.accepted",
          target: "control-center-sessions",
          environment,
          risk: "medium",
          result: "success",
          dryRun: false,
          summary: `Validated OIDC logout signal processed; revoked=${Number(result.revoked || 0)} replayed=${result.replayed === true}.`,
        });
      } catch {
        json(res, {
          error: "oidc_backchannel_logout_audit_unavailable",
          message: "OIDC back-channel logout was processed, but completion evidence is temporarily unavailable; retry safely.",
        }, 503);
        return;
      }
      json(res, { ok: true, replayed: result.replayed === true, revoked: Number(result.revoked || 0) });
      return;
    }

    if (url.pathname === "/logout" && req.method === "POST") {
      const session = await controlAuth.authenticate(req);
      if (!session.ok) {
        json(res, { error: "admin_auth_required", message: session.message }, session.status);
        return;
      }
      const csrf = await controlAuth.validateMutation(req, url, session);
      if (!csrf.ok) {
        json(res, { error: csrf.error || "csrf_rejected", message: csrf.message }, csrf.status);
        return;
      }
      appendAudit({
        action: "admin.logout.success",
        actor: session.identity.subject,
        target: session.identity.subject,
        environment,
        risk: "low",
        result: "success",
        dryRun: false,
        summary: "Administrative session revoked.",
      });
      res.setHeader("set-cookie", await controlAuth.logout(req));
      redirect(res, "/");
      return;
    }

    const resolvedOperation = resolveAuthorizationCapability(req.method, url.pathname, {
      rawPathname: rawRequestPathname(req.url),
    });
    const controlOperation = resolvedOperation.control === true ? resolvedOperation : null;
    if (controlOperation) req.controlCenterOperation = controlOperation;

    const session = await controlAuth.authenticate(req);
    if (!session.ok) {
      if (url.pathname.startsWith("/control/") || req.method !== "GET") {
        json(res, { error: "admin_auth_required", message: session.message }, session.status);
        return;
      }
      html(res, renderLogin(session.message), session.status);
      return;
    }

    const authorization = controlAuth.authorize(req, url, session);
    if (!authorization.ok) {
      json(res, { error: authorization.error || "admin_authorization_required", message: authorization.message, ...(authorization.reauthUrl ? { reauthUrl: authorization.reauthUrl } : {}) }, authorization.status);
      return;
    }

    const csrf = await controlAuth.validateMutation(req, url, authorization);
    if (!csrf.ok) {
      json(res, { error: csrf.error || "csrf_rejected", message: csrf.message }, csrf.status);
      return;
    }

    await requestIdentity.run({
      subject: session.identity.subject,
      role: session.role,
      requestId: rid(),
    }, async () => {
      const state = readState();
      const projects = discoverProjects(state);
      if (req.method !== "GET") invalidateControlContextCache();
      const context = req.method === "GET" && !url.pathname.startsWith("/control/")
        ? await buildCachedContext({ projects, state })
        : await buildContext({ projects, state });

    if (controlOperation) {
      await handleApi(req, res, url, context, controlOperation);
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

    if (req.method === "POST" && url.pathname === "/actions/vault-command") {
      await handleVaultCommand(req, res, context);
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

      htmlPage(req, res, renderControlCenter(context, url.searchParams));
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const status = error instanceof AuthRequestError ? error.status : 500;
    json(res, { error: status === 413 ? "payload_too_large" : "control_center_error", message: sanitizeMessage(message) }, status);
  }
});

server.listen(port, bindHost, () => {
  console.log(`control-center listening on ${bindHost}:${port} with ${controlAuth.mode} authentication`);
});

function rawRequestPathname(requestTarget) {
  const value = String(requestTarget || "/");
  const queryIndex = value.indexOf("?");
  return queryIndex < 0 ? value : value.slice(0, queryIndex);
}

async function shutdown() {
  statusEventBroker.close();
  server.close(async () => {
    await controlAuth.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);

async function handleApi(req, res, url, context, operation) {
  if (!operation?.classified || operation.control !== true) {
    notFound(res);
    return;
  }
  const method = operation.method;
  const parts = operation.canonicalPath.split("/").filter(Boolean);
  const payload = method === "POST" ? await readPayload(req) : {};

  try {
    // Security-sensitive operations dispatch directly from the same catalog
    // identity used by authorization. The legacy comparisons below consume
    // only the already-resolved canonical method/path for ordinary routes.
    switch (operation.operationId) {
      case "overview.read": return json(res, context.overview);
      case "advanced.section.read": return json(res, advancedControlSection(operation.parameters.sectionId, context));
      case "vault.inventory.read": return json(res, { items: context.vaultItems, overview: context.overview.vault });
      case "vault.secret.store": return json(res, planVaultSecretCreate(payload, context), 202);
      case "vault.import-existing": return json(res, planVaultSecretImportExisting(payload, context), 202);
      case "vault.secret.reveal": return json(res, planVaultSecretReveal(operation.parameters.vaultItemId, payload, context), 202);
      case "vault.secret.delete": return json(res, planVaultSecretDelete(operation.parameters.vaultItemId, payload, context), 202);
      case "database.create": return json(res, planDatabaseCreate(payload, context), 202);
      case "database.backup": return json(res, planDatabaseBackup(operation.parameters.databaseId, payload, context), 202);
      case "backup.summary.read": return json(res, context.backups);
      case "backup.records.read": return json(res, { records: context.backupRecords });
      case "backup.jobs.read": return json(res, { jobs: readBackupJobs() });
      case "backup.files.list": return json(res, readBackupFiles(url.searchParams.get("path") || ""));
      case "backup.file.preview": return json(res, readBackupPreview(url.searchParams.get("path") || ""));
      case "backup.run": return json(res, queueBackupRun(payload, context), 202);
      case "backup.file.delete": return json(res, applyBackupFileDelete(payload, context), 202);
      default: break;
    }

    if (method === "GET" && route(parts, "control", "overview")) return json(res, context.overview);
    if (method === "GET" && route(parts, "control", "status", "events", "stream")) {
      return await streamStatusRunEvents(req, res, url.searchParams.get("runId") || "");
    }
    if (method === "GET" && route(parts, "control", "status", "events")) {
      const runId = sanitizeIdentifier(url.searchParams.get("runId") || "");
      const limit = clampNumber(Number(url.searchParams.get("limit") || (runId ? 2000 : 200)), 1, 2000);
      return json(res, readStatusRunEventPage(limit, runId));
    }
    if (method === "GET" && route(parts, "control", "status")) {
      const statusEventPage = readStatusRunEventPage(
        clampNumber(Number(context.statusRun?.eventCount || 100), 1, 2000),
        context.statusRun?.id || "",
      );
      return json(res, {
        goNoGo: context.goNoGo,
        readiness: context.readiness,
        statusCatalog: statusExecutorCatalog(context),
        statusRun: context.statusRun,
        statusEvents: statusEventPage.events,
        statusEventsTruncated: statusEventPage.truncated,
      });
    }
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

    if (method === "GET" && route(parts, "control", "databases")) return json(res, { databases: context.databases, engines: context.databaseEngines, destructiveOperations: context.databaseDeleteOperations });
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
    if (method === "GET" && route(parts, "control", "vault")) return json(res, { items: context.vaultItems, overview: context.overview.vault });
    if (method === "POST" && route(parts, "control", "vault", "secrets")) return json(res, planVaultSecretCreate(payload, context), 202);
    if (method === "POST" && route(parts, "control", "vault", "import-existing")) return json(res, planVaultSecretImportExisting(payload, context), 202);
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "vault", "secrets", "reveal")) {
      return json(res, planVaultSecretReveal(parts[3], payload, context), 202);
    }
    if (method === "POST" && parts.length === 5 && route([parts[0], parts[1], parts[2], parts[4]], "control", "vault", "secrets", "delete")) {
      return json(res, planVaultSecretDelete(parts[3], payload, context), 202);
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
    if (method === "GET" && route(parts, "control", "backups", "jobs")) return json(res, { jobs: readBackupJobs() });
    if (method === "GET" && route(parts, "control", "backups", "files")) return json(res, readBackupFiles(url.searchParams.get("path") || ""));
    if (method === "GET" && route(parts, "control", "backups", "preview")) return json(res, readBackupPreview(url.searchParams.get("path") || ""));
    if (method === "POST" && route(parts, "control", "backups", "run")) return json(res, queueBackupRun(payload, context), 202);
    if (method === "POST" && route(parts, "control", "backups", "files", "delete")) return json(res, applyBackupFileDelete(payload, context), 202);
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
    if (error instanceof StatusEventStreamError && !res.headersSent) {
      return json(res, { error: error.code.toLowerCase(), message: error.message }, error.status);
    }
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
  const payload = await readPayload(req);
  const run = await runStatusVerification(context, {
    scope: payload.scope,
    category: payload.category,
    checkId: payload.checkId,
    runId: payload.runId,
  });
  appendStatusRun(run);
  appendAudit({
    action: "status.verify.run",
    target: run.target || "platform-infrastructure",
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
    else if (action === "update") operation = planDatabaseUpdate(payload.id || payload.databaseId || "", payload, context);
    else if (action === "delete") operation = planDatabaseDelete(payload.id || payload.databaseId || "", payload, context);
    else if (action === "delete-approve") operation = approveDatabaseDelete(payload.operationId || payload.id || "", payload, context);
    else if (action === "delete-execute") operation = executeDatabaseDelete(payload.operationId || payload.id || "", payload, context);
    else if (action === "credential") operation = planDatabaseCredentialUpdate(payload.id || payload.databaseId || "", payload, context);
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
  redirect(res, databaseCommandRedirect(payload, operation));
}

function databaseCommandRedirect(payload, operation) {
  const returnTo = sanitizeIdentifier(payload.returnTo || "");
  const projectId = sanitizeIdentifier(payload.projectId || operation?.details?.projectId || operation?.database?.projectId || "");
  const databaseId = sanitizeIdentifier(operation?.details?.databaseId || operation?.database?.id || "");
  if (returnTo === "project-detail" && projectId) {
    return `/?section=projects&project=${encodeURIComponent(projectId)}#project-databases`;
  }
  if (payload.openAfterCreate === "admin" && operation?.database) {
    const adminAction = databaseAdminAction(operation.database);
    return adminAction.href;
  }
  return `/?section=databases#database-${encodeURIComponent(databaseId)}`;
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
      renderTransientMessage(res, 409, "Accesso phpMyAdmin non configurato", `Non ho trovato credenziali MariaDB dedicate per ${databaseDisplayName(database)}. Salva una password per questo database dalla scheda applicazione, poi riapri phpMyAdmin.`);
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
      renderTransientMessage(res, 409, "Accesso phpPgAdmin non configurato", `Non ho trovato credenziali PostgreSQL limitate per ${databaseDisplayName(database)}. Configura il principal dedicato e il relativo credentialFile.`);
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

async function handleVaultCommand(req, res, context) {
  const payload = await readPayload(req);
  const action = String(payload.action || "");
  let operation;
  try {
    if (action === "create") operation = planVaultSecretCreate(payload, context);
    else if (action === "delete") operation = planVaultSecretDelete(payload.id || payload.itemId || "", payload, context);
    else if (action === "import-existing") operation = planVaultSecretImportExisting(payload, context);
    else throw new ValidationError("Unsupported vault action.");
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
  redirect(res, `/?section=vault#vault-${encodeURIComponent(operation.details?.itemId || operation.item?.id || "")}`);
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
    if (action === "backup") operation = queueBackupRun(payload, context);
    else if (action === "restore") operation = queueRestoreDrill(payload, context);
    else if (action === "delete-file") operation = applyBackupFileDelete(payload, context);
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
  redirect(res, backupCommandRedirect(payload, operation));
}

function backupCommandRedirect(payload, operation) {
  const returnTo = sanitizeIdentifier(payload.returnTo || "");
  const projectId = sanitizeIdentifier(payload.projectId || operation?.details?.projectId || "");
  if (returnTo === "project-detail" && projectId) {
    return `/?section=projects&project=${encodeURIComponent(projectId)}#project-backups`;
  }
  return "/?section=projects";
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
  const databasePrincipalBindings = readDatabasePrincipalsState().bindings;
  const databases = Object.values(readDatabasesState())
    .filter((database) => database && !database.deletedAt)
    .map((database) => {
      const binding = principalBindingFor(databasePrincipalBindings, database);
      return databaseRecord({
        ...database,
        principalBindingId: binding?.databaseId || database.principalBindingId || "",
        principalManaged: Boolean(binding),
        principalBindingStatus: binding?.status || database.principalBindingStatus || "legacy-unbound",
      });
    })
    .sort((a, b) => `${a.projectId}:${a.engine}:${a.name}`.localeCompare(`${b.projectId}:${b.engine}:${b.name}`));
  const databaseDeleteOperations = Object.values(readDatabaseDeleteOperationsState().operations)
    .filter((operation) => operation && operation.status !== "completed")
    .map((operation) => parseDatabaseDeleteOperation(operation))
    .sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
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
  const vaultItems = Object.values(readVaultState().items || {})
    .filter((item) => item && !item.deletedAt)
    .map((item) => vaultItemRecord(item))
    .sort((a, b) => `${a.projectId}:${a.environment}:${a.itemKey}`.localeCompare(`${b.projectId}:${b.environment}:${b.itemKey}`));
  const existingVaultCandidates = readExistingSecretCandidates();
  const existingVaultImport = summarizeExistingSecretImport(existingVaultCandidates, vaultItems);
  const workerJobsState = readWorkerJobsState();
  const defaultWorkerRuntimes = [
    workerRuntimeRecord({
      id: "enterprise-platform-alert-dispatcher",
      projectId: "platform",
      name: "Alert dispatcher",
      service: "platform-alert-dispatcher",
      status: "configured",
      queueName: "alerts",
      source: "compose-service",
    }),
    workerRuntimeRecord({
      id: "enterprise-backup-scheduler",
      projectId: "platform",
      name: "Backup scheduler",
      service: "backup-scheduler",
      status: "configured",
      queueName: "maintenance",
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
    jobScheduleRecord({ id: "backup-scheduler", projectId: "platform", name: "Backup scheduler", workerId: "enterprise-backup-scheduler", queueId: "maintenance", cronExpression: "0 */8 * * *", status: "configured", source: "compose-backup-scheduler", containerizedCron: true }),
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
    adminProtection: controlAuth.enabled ? "oidc-passkey-required" : "test-only-disabled",
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
  const backups = buildBackupInventory(backupRecords);
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
    alertRouting: "Prometheus routes to internal Alertmanager, then to the platform alert dispatcher with secret-backed delivery.",
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
    vault: { total: vaultItems.length, rotationDue: vaultItems.filter((item) => item.rotationStatus === "due").length, encryptedAtRest: true, importableExisting: existingVaultImport.importableCount },
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
  const context = {
    overview,
    projects,
    applications,
    domains,
    subdomains,
    network,
    webspaces,
    databases,
    databaseDeleteOperations,
    databaseEngines,
    databaseNameHints,
    storageProvider,
    storageBuckets,
    materialStores,
    sensitiveMaterials,
    vaultItems,
    existingVaultCandidates,
    existingVaultImport,
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
  context.statusRows = opsStatusRows(context);
  return context;
}

function controlContextKey({ projects, state }) {
  return sha256(JSON.stringify({
    projects: projects.map((project) => ({
      enabled: project.enabled,
      host: project.host,
      runtime: project.runtime,
      slug: project.slug,
      status: project.status,
    })),
    state,
  }));
}

function invalidateControlContextCache() {
  controlContextCache.key = "";
  controlContextCache.value = null;
  controlContextCache.expiresAt = 0;
  controlContextCache.pending = null;
}

async function buildCachedContext(input) {
  const key = controlContextKey(input);
  const now = Date.now();
  if (controlContextCache.value && controlContextCache.key === key && controlContextCache.expiresAt > now) {
    return controlContextCache.value;
  }
  if (controlContextCache.pending && controlContextCache.key === key) return controlContextCache.pending;
  controlContextCache.key = key;
  const pending = buildContext(input).then((context) => {
    if (controlContextCache.pending === pending && controlContextCache.key === key) {
      controlContextCache.value = context;
      controlContextCache.expiresAt = Date.now() + controlContextCacheTtlMs;
      controlContextCache.pending = null;
    }
    return context;
  }, (error) => {
    if (controlContextCache.pending === pending) invalidateControlContextCache();
    throw error;
  });
  controlContextCache.pending = pending;
  return pending;
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
      advancedSections: ["monitoring"],
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
        adminAuthRequired: controlAuth.enabled,
        adminVerifierConfigured: controlAuth.mode === "oidc-passkey",
        sessionPolicy: "PostgreSQL-backed; revocable; HttpOnly; Secure; SameSite=Lax",
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

async function runStatusVerification(context, options = {}) {
  const request = normalizeStatusRunRequest(options);
  const startedAt = new Date().toISOString();
  const startedMs = Date.now();
  const runId = normalizeStatusRunId(options.runId, startedMs);
  if (readStatusRunEvents(1, runId).length) throw new ValidationError("Status run ID already exists.");
  const runners = statusRunCheckRunners(context);
  const selected = selectStatusRunChecks(context, runners, request);
  const catalog = selected.length ? selected : [{
    id: "status-selection-empty",
    category: request.category || "operational-evidence",
    executionMode: "evidence-validation",
    required: false,
    run: () => statusRunCheck({
      id: "status-selection-empty",
      title: "Selezione test vuota",
      category: request.category || "operational-evidence",
      source: "Portal",
      status: "plan-only",
      detail: "Nessun controllo disponibile per la selezione richiesta.",
      nextAction: "Scegli una sezione con controlli o rilancia tutti i test reali.",
      required: false,
    }),
  }];
  const execution = await executeStatusChecks({
    runId,
    checks: catalog,
    delayMs: statusRunStepDelayMs,
    timeoutMs: statusRunCheckTimeoutMs,
    onEvent: appendStatusRunEvent,
  });
  const checks = execution.checks;

  const summary = statusRunSummary(checks);
  return sanitizeEvent({
    id: runId,
    generatedAt: startedAt,
    finishedAt: new Date().toISOString(),
    durationMs: Date.now() - startedMs,
    status: summary.failed ? "failed" : summary.pending ? "warning" : "passed",
    scope: "platform-infrastructure",
    target: statusRunTargetLabel(request),
    requestedScope: request.scope,
    requestedCategory: request.category,
    requestedCheckId: request.checkId,
    destructive: false,
    providerTouched: false,
    dockerTouched: false,
    summary,
    checks,
    eventCount: execution.events.length,
  });
}

function normalizeStatusRunRequest(options = {}) {
  const scope = sanitizeIdentifier(options.scope || "all") || "all";
  return {
    scope: ["all", "category", "check"].includes(scope) ? scope : "all",
    category: sanitizeIdentifier(options.category || ""),
    checkId: sanitizeIdentifier(options.checkId || ""),
  };
}

function normalizeStatusRunId(value, startedMs = Date.now()) {
  const candidate = String(value || "").trim();
  if (!candidate) return `status-${startedMs.toString(36)}`;
  if (!/^status-[a-z0-9][a-z0-9-]{7,79}$/.test(candidate)) throw new ValidationError("Invalid status run ID.");
  return candidate;
}

function statusRunTargetLabel(request) {
  if (request.scope === "check" && request.checkId) return `check:${request.checkId}`;
  if (request.scope === "category" && request.category) return `category:${request.category}`;
  return "platform-infrastructure";
}

function statusRunCheckRunners(context) {
  const goNoGo = context.goNoGo || {};
  const readinessTotal = Number(context.readiness?.summary?.total || 0);
  return [
    {
      id: "portal-through-waf",
      category: "domain-edge",
      executionMode: "probe",
      run: () => statusHttpCheck({
        id: "portal-through-waf",
        title: "Portal attraverso WAF",
        category: "domain-edge",
        source: "Test reale",
        url: `${statusWafUrl}/`,
        headers: statusProbeHeaders(),
        okStatuses: [200],
        bodyIncludes: "Admin Control Center",
        okDetail: "La richiesta passa da WAF/Traefik e renderizza il Portal.",
        failAction: "Verifica WAF, Traefik e host portal prima di dichiarare lo stato online.",
      }),
    },
    {
      id: "waf-sensitive-file-block",
      category: "security",
      executionMode: "probe",
      run: () => statusHttpCheck({
        id: "waf-sensitive-file-block",
        title: "WAF blocca file sensibili",
        category: "security",
        source: "Test reale",
        url: `${statusWafUrl}/.env`,
        headers: statusProbeHeaders(),
        okStatuses: [403, 404, 406],
        okDetail: "La route pubblica non espone file .env.",
        failAction: "Blocca subito l'esposizione di file sensibili su WAF/Traefik.",
      }),
    },
    {
      id: "go-no-go-report-readable",
      category: "go-live",
      executionMode: "evidence-validation",
      run: () => statusRunCheck({
        id: "go-no-go-report-readable",
        title: "Report go/no-go leggibile",
        category: "go-live",
        source: "Report",
        status: goNoGo.reportPath ? "passed" : "pending-live-proof",
        detail: goNoGo.reportPath ? `Report caricato: ${goNoGo.reportPath}` : "Nessun report production-go-no-go trovato.",
        nextAction: goNoGo.reportPath ? "Mantieni il report aggiornato dopo ogni cambio infrastruttura." : "Esegui il go/no-go completo dal server e conserva il report.",
      }),
    },
    {
      id: "go-no-go-verdict",
      category: "go-live",
      executionMode: "evidence-validation",
      run: () => statusRunCheck({
        id: "go-no-go-verdict",
        title: "Decisione produzione",
        category: "go-live",
        source: "Report",
        status: goNoGo.status === "go" ? "passed" : goNoGo.reportPath ? "no-go" : "pending-live-proof",
        detail: goNoGo.status === "go"
          ? "Il report più recente dice GO LIVE."
          : `Il report più recente dice ${String(goNoGo.status || "unknown").toUpperCase()} con ${Number(goNoGo.summary?.blockingRequired || goNoGo.blockers?.length || 0)} blocchi.`,
        nextAction: goNoGo.status === "go" ? "Procedi solo con backup e rollback pronti." : "Chiudi i requisiti aperti, poi rilancia il controllo.",
      }),
    },
    {
      id: "readiness-matrix-readable",
      category: "governance",
      executionMode: "evidence-validation",
      run: () => statusRunCheck({
        id: "readiness-matrix-readable",
        title: "Matrice readiness caricata",
        category: "governance",
        source: "Report",
        status: readinessTotal > 0 ? "passed" : "needs-work",
        detail: readinessTotal > 0 ? `${readinessTotal} controlli readiness letti dai manifest.` : "Nessun controllo readiness disponibile.",
        nextAction: readinessTotal > 0 ? "Mantieni governance/production-readiness.json e enterprise-requirements.json coerenti." : "Ripristina i manifest governance prima del prossimo go live.",
      }),
    },
  ];
}

function selectStatusRunChecks(context, runners, request) {
  const rows = statusRowsForContext(context);
  const runnerById = new Map(runners.map((runner) => [runner.id, runner]));
  if (request.scope === "check" && request.checkId) {
    const runner = runnerById.get(request.checkId);
    if (runner) return [runner];
    const row = rows.find((item) => item.technicalId === request.checkId || item.id === request.checkId);
    return row ? [statusEvidenceRunner(row)] : [];
  }
  if (request.scope === "category" && request.category) {
    const categoryRunners = runners.filter((runner) => runner.category === request.category);
    const runnerIds = new Set(categoryRunners.map((runner) => runner.id));
    const evidenceChecks = rows
      .filter((row) => row.category === request.category)
      .filter((row) => !runnerIds.has(row.technicalId))
      .map(statusEvidenceRunner);
    return [...categoryRunners, ...evidenceChecks];
  }
  const runnerIds = new Set(runners.map((runner) => runner.id));
  return [
    ...runners,
    ...rows.filter((row) => !runnerIds.has(row.technicalId)).map(statusEvidenceRunner),
  ];
}

function statusEvidenceRunner(row) {
  const externalRequired = ["authorization-required", "pending-live-proof", "pending-provider"].includes(row.status);
  return {
    id: row.technicalId || row.id,
    title: row.control || row.technicalId || "Controllo",
    category: row.category || "operational-evidence",
    required: row.required,
    executionMode: externalRequired ? "external-required" : "evidence-validation",
    run: () => statusEvidenceValidationCheck(row),
  };
}

function statusEvidenceValidationCheck(row) {
  return statusRunCheck({
    id: row.technicalId || row.id,
    title: row.control || row.technicalId || "Controllo",
    category: row.category || "operational-evidence",
    source: row.source || "Validazione evidence",
    status: row.status,
    detail: row.reason || "Evidence ricontrollata dal catalogo Stato.",
    nextAction: row.status === "passed" ? "Nessuna azione immediata." : row.action,
    required: row.required,
  });
}

function statusExecutorCatalog(context) {
  const checks = selectStatusRunChecks(context, statusRunCheckRunners(context), { scope: "all", category: "", checkId: "" });
  return checks.map((check) => ({
    id: check.id,
    category: check.category,
    executionMode: check.executionMode,
    required: check.required !== false,
  }));
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
  const failed = checks.filter((check) => ["failed", "needs-work", "no-go"].includes(check.status)).length;
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
  "enterprise-production-360-coverage": "Copertura enterprise 360",
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
  "backup-scheduler": { directory: "local-checks", prefix: "backup-scheduler-", maxAgeHours: 72, pass: "backup-scheduler-runtime" },
  "backup-secret-manager-metadata": { directory: "backups", prefix: "secret-manager-backup-", maxAgeHours: 72, pass: "backup-success" },
  "certificate-expiry-check": { directory: "local-checks", prefix: "certificate-expiry-check-", maxAgeHours: 168, pass: "local-check-passed", command: "certificate-expiry-check" },
  "chaos-profile": { directory: "chaos", prefix: "chaos-profile-", maxAgeHours: 168, pass: "status-passed" },
  "compliance-evidence": { directory: "governance", prefix: "compliance-evidence-", maxAgeHours: 168, pass: "compliance-evidence" },
  "compose-healthcheck-coverage": { directory: "healthchecks", prefix: "healthcheck-coverage-", maxAgeHours: 168, pass: "healthcheck-coverage" },
  "control-center-tests": { directory: "local-checks", prefix: "control-center-tests-", maxAgeHours: 168, pass: "local-check-passed", command: "control-center-tests" },
  "data-classification": { directory: "governance", prefix: "data-classification-", maxAgeHours: 168, pass: "data-classification" },
  "dependency-hygiene": { directory: "local-checks", prefix: "dependency-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "dependency-hygiene" },
  "dr-evidence": { directory: "dr", prefix: "dr-evidence-", maxAgeHours: 168, pass: "dr-evidence-complete" },
  "dr-readiness-check": { directory: "dr", prefix: "dr-evidence-", maxAgeHours: 168, pass: "dr-evidence-complete" },
  "evidence-bundle": { directory: "local-checks", prefix: "evidence-bundle-", maxAgeHours: 168, pass: "local-check-passed", command: "evidence-bundle" },
  "evidence-bundle-verify": { directory: "evidence-bundle-verify", prefix: "evidence-bundle-verify-", maxAgeHours: 168, pass: "status-passed" },
  "enterprise-check": { directory: "local-checks", prefix: "enterprise-check-", maxAgeHours: 168, pass: "local-check-passed", command: "enterprise-check" },
  "enterprise-hardening-audit": { directory: "local-checks", prefix: "enterprise-hardening-audit-", maxAgeHours: 168, pass: "local-check-passed", command: "enterprise-hardening-audit" },
  "enterprise-production-360-coverage": { directory: "governance", prefix: "enterprise-production-360-coverage-", maxAgeHours: 168, pass: "enterprise-production-360-coverage" },
  "enterprise-requirements-check": { directory: "enterprise-requirements", prefix: "enterprise-requirements-", maxAgeHours: 168, pass: "repo-report-passed" },
  "enterprise-10-check": { directory: "enterprise-requirements", prefix: "enterprise-requirements-", maxAgeHours: 168, pass: "repo-report-passed" },
  "full-restore-drill": { directory: "restore-drills", prefix: "full-restore-drill-", maxAgeHours: 168, pass: "status-success" },
  "failure-tests": { directory: "failure-tests", prefix: "failure-tests-", maxAgeHours: 168, pass: "failure-tests" },
  "feature-flags-kill-switches": { directory: "governance", prefix: "feature-flags-kill-switches-", maxAgeHours: 168, pass: "feature-flags-kill-switches" },
  "fault-injection-tests": { directory: "fault-injection", prefix: "fault-injection-tests-", maxAgeHours: 168, pass: "status-passed" },
  "generate-sbom": { directory: "local-checks", prefix: "generate-sbom-", maxAgeHours: 168, pass: "local-check-passed", command: "generate-sbom" },
  "governance-check": { directory: "local-checks", prefix: "governance-check-", maxAgeHours: 168, pass: "local-check-passed", command: "governance-check" },
  "github-branch-protection": { directory: "go-live", prefix: "pre-go-live-evidence-", maxAgeHours: 168, pass: "pre-go-live-step", step: "github-branch-protection-verify-remote" },
  "github-environments": { directory: "go-live", prefix: "pre-go-live-evidence-", maxAgeHours: 168, pass: "pre-go-live-step", step: "github-environments-verify-remote" },
  "ha-single-node-risk-acceptance": { directory: "governance", prefix: "ha-single-node-risk-acceptance-", maxAgeHours: 168, pass: "ha-single-node-risk-acceptance" },
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
  "pentest-readiness": { directory: "security", prefix: "pentest-readiness-", maxAgeHours: 168, pass: "pentest-readiness" },
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
  "sign-images": { directory: "release", prefix: "github-sigstore-attestation-", maxAgeHours: 168, pass: "status-passed" },
  "static-security-check": { directory: "local-checks", prefix: "static-security-check-", maxAgeHours: 168, pass: "local-check-passed", command: "static-security-check" },
  "supply-chain-hygiene": { directory: "local-checks", prefix: "supply-chain-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "supply-chain-hygiene" },
  "testing-hygiene": { directory: "local-checks", prefix: "testing-hygiene-", maxAgeHours: 168, pass: "local-check-passed", command: "testing-hygiene" },
  "validate-local-secrets": { directory: "secret-rotation", prefix: "secret-rotation-evidence-", maxAgeHours: 168, pass: "secret-rotation" },
  "vulnerability-disclosure": { directory: "security", prefix: "vulnerability-disclosure-", maxAgeHours: 168, pass: "vulnerability-disclosure" },
  "sign-existing-postgres-backups": { directory: "postgres-backup-signatures", prefix: "postgres-backup-signatures-", maxAgeHours: 168, pass: "postgres-backup-signatures" },
  "vps-go-live": { directory: "vps-go-live", prefix: "vps-go-live-", excludePrefixes: ["vps-go-live-plan-"], maxAgeHours: 168, pass: "vps-go-live-live" },
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
      "enterprise-production-360-coverage",
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
      "backup-scheduler",
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
      reportPath: evidence.reportPath,
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
    const guidance = readinessRequirementGuidance(readinessMatch.requirement);
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
      detail: guidance?.reason || `Checklist: ${readinessMatch.requirement.title}. Stato repo: ${readinessMatch.requirement.sourceState}; evidence: ${readinessMatch.requirement.evidenceCount}.`,
      nextAction: guidance?.action || requirementAction || base.nextAction,
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
  const report = latestDocumentedReport(spec.directory, spec.prefix, spec);
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

function readPassedDocumentedStatusEvidence(command) {
  const spec = documentedStatusEvidenceSpecs[command];
  if (!spec) return null;
  const report = latestDocumentedReport(spec.directory, spec.prefix, spec);
  if (!report) return null;
  const age = reportAgeDetail(report.payload, spec.maxAgeHours);
  if (!age.fresh || !documentedEvidencePassed(report.payload, spec)) return null;
  return {
    payload: report.payload,
    reportPath: report.reportPath,
    detail: `Report reale valido: ${report.reportPath}; ${age.detail}.`,
  };
}

function documentedEvidenceExplicitlyFailed(payload, spec) {
  const status = String(payload?.status || "").toLowerCase();
  if (["failed", "failure", "error"].includes(status)) return true;
  if (["planned", "plan", "dry-run", "skipped", "pending"].includes(status)) return false;
  if (["passed", "success", "go"].includes(status)) return !documentedEvidencePassed(payload, spec);
  return false;
}

function latestDocumentedReport(directoryName, prefix, spec = {}) {
  const root = path.resolve(docsRoot);
  const directory = path.resolve(root, "reports", path.basename(directoryName));
  if (!directory.startsWith(`${root}${path.sep}`) || !existsSync(directory)) return null;
  try {
    const cleanPrefix = String(prefix || "").replace(/[^a-z0-9-]/gi, "");
    const excludePrefixes = Array.isArray(spec.excludePrefixes)
      ? spec.excludePrefixes.map((item) => String(item || "").replace(/[^a-z0-9-]/gi, "")).filter(Boolean)
      : [];
    const fileName = readdirSync(directory)
      .filter((name) => name.startsWith(cleanPrefix) && name.endsWith(".json"))
      .filter((name) => !excludePrefixes.some((excludedPrefix) => name.startsWith(excludedPrefix)))
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
    case "backup-scheduler-runtime":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.command === "backup-scheduler"
        && payload.container?.state === "running"
        && payload.container?.health === "healthy"
        && payload.schedule?.everyEightHours === true
        && Number(payload.schedule?.retentionKeepLast || 0) === 42
        && Number(payload.schedule?.maxRepositoryBytes || 0) === 2_500_000_000_000
        && Number(payload.summary?.failedChecks || 0) === 0
        && Number(payload.summary?.missingJobs || 0) === 0
        && Number(payload.summary?.missingEnvKeys || 0) === 0
        && Number(payload.summary?.jobsNotEveryEightHours || 0) === 0;
    case "compliance-evidence":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.command === "compliance-evidence"
        && payload.compliance?.approved === true
        && payload.compliance?.formalCertificationClaimed === false
        && payload.compliance?.gdprLikeMapping === true
        && payload.compliance?.soc2LikeMapping === true
        && Number(payload.summary?.failedChecks || 0) === 0;
    case "data-classification":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.command === "data-classification"
        && payload.classification?.approved === true
        && payload.classification?.hostedApplicationDataOutOfScope === true
        && Array.isArray(payload.classification?.levels)
        && ["Public", "Internal", "Confidential", "Secret", "Restricted"].every((level) => payload.classification.levels.includes(level))
        && Number(payload.summary?.failedChecks || 0) === 0;
    case "dr-evidence-complete":
      return status === "passed"
        && Array.isArray(payload.issues)
        && payload.issues.length === 0
        && payload.offsiteEvidence?.latestRestoreOffsite === true
        && payload.offsiteEvidence?.latestRestoreCoverage?.complete === true;
    case "enterprise-production-360-coverage":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.command === "enterprise-production-360-coverage"
        && payload.semantics?.productionGoLiveDecision === false
        && Number(payload.summary?.invalidRefs || 0) === 0
        && Number(payload.summary?.domains || 0) >= Number(payload.summary?.expectedDomains || 0)
        && Number(payload.summary?.controls || 0) >= Number(payload.summary?.minimumControls || 0);
    case "feature-flags-kill-switches":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.command === "feature-flags-kill-switches"
        && payload.killSwitches?.operational === true
        && payload.killSwitches?.applicationFlagsOutOfScope === true
        && payload.killSwitches?.destructiveVolumeActionsAllowed === false
        && Number(payload.killSwitches?.switchCount || 0) >= 6
        && Number(payload.summary?.failedChecks || 0) === 0;
    case "healthcheck-coverage":
      return status === "passed" && Number(payload.summary?.missingHealthchecks || 0) === 0;
    case "ha-single-node-risk-acceptance":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.command === "ha-single-node-risk-acceptance"
        && payload.decision?.singleNodeRiskAccepted === true
        && payload.decision?.haClaimed === false
        && payload.decision?.multiNodeClaimed === false
        && Number(payload.summary?.failedChecks || 0) === 0;
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
    case "pentest-readiness":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.mode === "readiness-plan"
        && payload.readiness?.approved === true
        && payload.externalProfessionalPentest?.requiredBeforeEnterpriseLaunch === true
        && Number(payload.summary?.failedChecks || 0) === 0;
    case "vulnerability-disclosure":
      return status === "passed"
        && payload.scope === "platform-infrastructure"
        && payload.command === "vulnerability-disclosure"
        && payload.process?.publishable === true
        && payload.process?.approved === true
        && payload.channel?.securityPolicyPresent === true
        && Number(payload.summary?.failedChecks || 0) === 0;
    case "pre-go-live-step":
      return Array.isArray(payload.steps)
        && payload.steps.some((step) => step?.name === spec.step && step.status === "passed");
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
    let localEvidence = null;
    if (prefix === "enterprise") {
      const requirementId = sanitizeIdentifier(requirement.id || "");
      if (requirementId === "pentest") localEvidence = readDocumentedStatusEvidence("pentest-readiness");
      if (requirementId === "vulnerability-disclosure") localEvidence = readDocumentedStatusEvidence("vulnerability-disclosure");
      if (requirementId === "feature-flags-kill-switch") localEvidence = readDocumentedStatusEvidence("feature-flags-kill-switches");
      if (requirementId === "compliance-gdpr-soc2-like") localEvidence = readDocumentedStatusEvidence("compliance-evidence");
      if (requirementId === "data-classification") localEvidence = readDocumentedStatusEvidence("data-classification");
      if (requirementId === "ha-multi-node") localEvidence = readDocumentedStatusEvidence("ha-single-node-risk-acceptance");
    }
    const linkedGoNoGo = (requirement.liveProofChecks || [])
      .map((name) => (context.goNoGo?.checks || []).find((check) => check.name === name))
      .find(Boolean);
    const displayGoNoGo = linkedGoNoGo ? goNoGoDisplayCheck(linkedGoNoGo, prefix) : null;
    const rawStatus = localEvidence?.status || displayGoNoGo?.status || requirement.status;
    const requirementAction = documentedReadinessAction(requirement);
    const guidance = readinessRequirementGuidance(requirement, displayGoNoGo);
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
      source: localEvidence ? `${manifest.title || "Governance"} / report` : manifest.title || "Governance",
      status,
      detail: localEvidence
        ? localEvidence.detail
        : displayGoNoGo
        ? (passed ? (displayGoNoGo.detail || "Requirement coperto dal report go/no-go.") : guidance?.reason || simpleBlockerReason(displayGoNoGo))
        : `Manifest governance: ${requirement.sourceState}; evidence repo: ${requirement.evidenceCount}; live proof: ${requirement.liveProofStatus}.`,
      nextAction: localEvidence
        ? (passed ? "Mantieni il report pentest readiness aggiornato e pianifica il pentest esterno prima del lancio enterprise." : localEvidence.nextAction)
        : displayGoNoGo
        ? (passed ? "Mantieni il report aggiornato dopo ogni modifica." : guidance?.action || simpleBlockerAction(displayGoNoGo))
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
  const guidance = readinessRequirementGuidance(requirement);
  if (guidance?.action) return `${guidance.action}${checks}`;
  if (requirement.liveProofRequired) {
    return `Completa la prova live o provider per "${requirement.title}" e archivia il report non-secret.${checks}`;
  }
  return `Esegui la verifica documentata per "${requirement.title}" e conserva l'evidence aggiornata.${checks}`;
}

function readinessRequirementGuidance(requirement, linkedCheck = null) {
  const id = sanitizeIdentifier(requirement?.id || linkedCheck?.name || "");
  const title = sanitizeMessage(requirement?.title || "");
  const linkedText = `${linkedCheck?.name || ""} ${linkedCheck?.blocker || ""} ${linkedCheck?.detail || ""}`.toLowerCase();
  const preGoLiveEvidence = linkedText.includes("pre-go-live") || (requirement?.liveProofChecks || []).includes("pre-go-live-evidence-complete");
  const entries = {
    "real-dns": {
      reason: "Manca la prova su dominio reale: DNS pubblico, dominio finale e production preflight non sono ancora verificati fuori dalla LAN.",
      action: "Configura il dominio pubblico definitivo su Cloudflare/DNS, imposta gli host finali e rilancia production-preflight e pre-go-live evidence con il dominio reale.",
    },
    "public-https-acme": {
      reason: "Manca la prova HTTPS pubblica: certificati, DNS e raggiungibilita esterna non sono ancora verificati sul dominio finale.",
      action: "Verifica HTTPS pubblico, certificati e monitor esterno sul dominio reale; poi rilancia external-uptime-check, certificate-expiry-check e pre-go-live evidence.",
    },
    "remote-ci-cd": {
      reason: "GitHub Actions ora passa, ma manca la configurazione runtime/provider per il deploy controllato e il pre-go-live completo.",
      action: "Completa variabili/secrets GitHub Actions per staging/production, in particolare DAST_TARGET, PUBLIC_API_HEALTH_URL, Cloudflare evidence e provider uptime, poi rilancia pre-go-live con verifyRemote.",
    },
    "automatic-ci-cd-deploy": {
      reason: "La workflow GitHub passa, ma il deploy automatico non e' ancora provato con tutte le variabili/secrets di produzione e i provider live.",
      action: "Completa GitHub environment production/staging con variabili e secrets reali, conserva l'evidence del run e rilancia pre-go-live evidence.",
    },
    "waf-rate-limit-bot-protection": {
      reason: "Manca la prova dal public edge: WAF, rate limit e protezione bot sono configurati localmente ma non verificati su Cloudflare/dominio reale.",
      action: "Configura Cloudflare WAF/rate limit sul dominio pubblico, esegui WAF smoke e rate-limit evidence dal public edge, poi archivia il report.",
    },
    "hosted-workload-isolation": {
      reason: "Manca la prova di routing produzione per workload ospitati: wildcard DNS, Traefik e project-router non sono ancora verificati sul dominio reale.",
      action: "Verifica wildcard DNS e routing dei progetti sul dominio pubblico senza accoppiare codice app all'infra; conserva il report project-router/WAF.",
    },
    "ha-multi-node": {
      reason: "Manca una decisione/prova HA: l'ambiente attuale e' single-node e non dimostra multi-node readiness.",
      action: "Aggiungi un target multi-node oppure documenta e approva esplicitamente il rischio single-node per questa fase; poi archivia la decisione nel report pre-go-live.",
    },
    "staging-production-parity": {
      reason: "Manca staging separato: non c'e' ancora prova di ambiente staging distinto da produzione con host, secrets, volumi e target propri.",
      action: "Configura staging separato, imposta DAST_TARGET su GitHub Actions e verifica compose/route/secrets staging prima del go-live.",
    },
    "staging-separated": {
      reason: "Manca staging separato: non c'e' ancora prova di ambiente staging distinto da produzione con host, secrets, volumi e target propri.",
      action: "Configura staging separato, imposta DAST_TARGET su GitHub Actions e verifica compose/route/secrets staging prima del go-live.",
    },
    "operations-runbook": {
      reason: "Il runbook esiste, ma manca ancora l'aggancio ai report finali reali di produzione per dominio, provider e restore off-site.",
      action: "Dopo production preflight, Cloudflare/uptime e off-site restore, aggiorna i riferimenti ai report reali e rilancia production-readiness-live.",
    },
    "rate-limiting": {
      reason: "Manca la prova pubblica del rate limiting: i controlli locali passano, ma il comportamento dal public edge non e' ancora verificato.",
      action: "Esegui rate-limit evidence e WAF smoke contro il dominio pubblico/Cloudflare, poi conserva il report non-secret.",
    },
    "tls-https-production-ready": {
      reason: "Manca la prova TLS pubblica: HTTPS e monitor esterno devono essere verificati sul dominio finale.",
      action: "Configura dominio pubblico e certificati, verifica HTTPS da provider esterno e rilancia production-preflight.",
    },
    "production-email-dns": {
      reason: "Manca prova DNS email/alert produzione: SPF/DKIM/DMARC e delivery alert non sono ancora verificati sul dominio reale.",
      action: "Configura record email del dominio e provider SMTP/alert, esegui alert-evidence e conserva il report.",
    },
  };
  if (entries[id]) return entries[id];
  if (preGoLiveEvidence) {
    return {
      reason: title
        ? `Manca il pre go-live completo per "${title}": servono production preflight reale, provider live e restore off-site dove richiesto.`
        : "Manca il pre go-live completo: servono production preflight reale, provider live e restore off-site dove richiesto.",
      action: "Completa dominio/provider mancanti, GitHub Actions runtime config e off-site restore; poi rilancia pre-go-live-evidence con includeProductionPreflight, includeOffsiteRestoreDryRun e verifyGithubRemote.",
    };
  }
  return null;
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

function italianDateTimeLabel(value) {
  try {
    return new Intl.DateTimeFormat("it-IT", {
      day: "2-digit",
      hour: "2-digit",
      hour12: false,
      minute: "2-digit",
      month: "2-digit",
      second: "2-digit",
      timeZone: "Europe/Rome",
      timeZoneName: "short",
      year: "numeric",
    }).format(value instanceof Date ? value : new Date(value));
  } catch {
    return value instanceof Date ? value.toISOString() : String(value || "");
  }
}

function relativeTimeLabel(value, now = Date.now()) {
  const timestamp = Date.parse(value instanceof Date ? value.toISOString() : String(value || ""));
  if (!Number.isFinite(timestamp)) return "data non valida";
  const elapsedSeconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (elapsedSeconds < 60) return "ora";
  const minutes = Math.floor(elapsedSeconds / 60);
  if (minutes < 60) return `${minutes} min fa`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} h fa`;
  const days = Math.floor(hours / 24);
  return `${days} g fa`;
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
      modifiedAt: italianDateTimeLabel(stat.mtime),
      browsable: stat.isDirectory() && !isSymlink,
    };
  } catch {
    return null;
  }
}

function backupFamilySpecs() {
  return [
    { id: "applications", label: "Applicazioni", command: "backup-applications", restoreCommand: "", reportPrefix: "applications-backup-" },
    { id: "postgres", label: "PostgreSQL", command: "backup-postgres", restoreCommand: "restore-test-postgres", reportPrefix: "postgres-backup-" },
    { id: "mariadb", label: "MariaDB", command: "backup-mariadb", restoreCommand: "restore-test-mariadb", reportPrefix: "mariadb-backup-" },
    { id: "minio", label: "MinIO", command: "backup-minio", restoreCommand: "restore-test-minio", reportPrefix: "minio-backup-" },
    { id: "keycloak", label: "Keycloak", command: "backup-keycloak", restoreCommand: "restore-test-keycloak", reportPrefix: "keycloak-backup-" },
    { id: "secret-manager", label: "Secret vault", command: "backup-secret-manager-metadata", restoreCommand: "restore-test-secret-manager-metadata", reportPrefix: "secret-manager-backup-" },
  ];
}

function buildBackupInventory(records = []) {
  const files = safeReadBackupFiles("");
  const jobs = readBackupJobs();
  const families = backupFamilySpecs().map(readBackupFamily);
  const schedulerReport = latestDocumentedReport("local-checks", "backup-scheduler-");
  const drReport = latestDocumentedReport("dr", "dr-evidence-");
  const offsiteRestoreReport = latestDocumentedReport("offsite-restore-drills", "offsite-restore-drill-restore-");
  const schedulerPayload = schedulerReport?.payload || {};
  const drPayload = drReport?.payload || {};
  const offsitePayload = offsiteRestoreReport?.payload || {};
  const schedulerPassed = String(schedulerPayload.status || "").toLowerCase() === "passed";
  const offsitePassed = String(offsitePayload.status || "").toLowerCase() === "success";
  const localFamiliesPassed = families.length > 0 && families.every((family) => family.status === "success");
  const rootSummary = backupRootSummary(files);
  const scheduler = {
    status: schedulerPassed ? "running" : schedulerReport ? "needs-work" : "missing",
    label: schedulerPassed ? "Attivo" : schedulerReport ? "Da verificare" : "Nessuna prova",
    reportPath: schedulerReport?.reportPath || "",
    ageLabel: schedulerReport ? relativeTimeLabel(schedulerPayload.generatedAt) : "",
    containerState: schedulerPayload.container?.state || "non provato",
    containerHealth: schedulerPayload.container?.health || "non provato",
    everyEightHours: schedulerPayload.schedule?.everyEightHours === true,
    retentionKeepLast: Number(schedulerPayload.schedule?.retentionKeepLast || 0),
    maxRepositoryBytes: Number(schedulerPayload.schedule?.maxRepositoryBytes || 0),
    requiredJobs: Array.isArray(schedulerPayload.schedule?.requiredJobs) ? schedulerPayload.schedule.requiredJobs : [],
    missingJobs: Array.isArray(schedulerPayload.schedule?.missingJobs) ? schedulerPayload.schedule.missingJobs : [],
  };
  const dr = {
    status: String(drPayload.status || "").toLowerCase() === "passed" || drPayload.mode ? "available" : drReport ? "needs-work" : "missing",
    label: drReport ? "Report presente" : "Nessun report",
    reportPath: drReport?.reportPath || "",
    ageLabel: drReport ? relativeTimeLabel(drPayload.generatedAt) : "",
    rpoMinutes: Number(drPayload.targets?.rpoMinutes || 0),
    rtoMinutes: Number(drPayload.targets?.rtoMinutes || 0),
    familyCount: Array.isArray(drPayload.rpoEvidence?.backupFamilies) ? drPayload.rpoEvidence.backupFamilies.length : 0,
    fullRestoreReport: drPayload.rtoEvidence?.latestFullRestoreReport || "",
  };
  const offsite = {
    status: offsitePassed ? "success" : offsiteRestoreReport ? "needs-work" : "missing",
    label: offsitePassed ? "Provato" : offsiteRestoreReport ? "Da verificare" : "Nessuna prova",
    configured: process.env.BACKUP_SCHEDULER_ENABLE_OFFSITE === "true" || Boolean(offsitePayload.restic?.repositoryConfigured),
    reportPath: offsiteRestoreReport?.reportPath || "",
    ageLabel: offsiteRestoreReport ? relativeTimeLabel(offsitePayload.generatedAt || offsitePayload.finishedAt) : "",
    repositoryType: offsitePayload.restic?.repositoryType || "non esposto",
    repositoryOffsite: offsitePayload.restic?.repositoryOffsite === true,
    snapshotId: offsitePayload.snapshot?.shortId || "",
    snapshotTime: offsitePayload.snapshot?.time || "",
    snapshotCountForTag: Number(offsitePayload.snapshotCountForTag || 0),
  };
  return sanitizeEvent({
    mode: environment,
    manualBackup: "plan-only-from-control-center",
    restoreDrill: "available-through-infra-ops",
    offsite: offsite.status === "success" ? "verified-off-site" : offsite.configured ? "configured" : "not-configured",
    rpoRto: dr.reportPath ? "reported-by-dr-evidence" : "missing-dr-evidence",
    root: rootSummary,
    families,
    scheduler,
    dr,
    offsiteRestore: offsite,
    executor: {
      status: existsSync(backupJobsDir) ? "available" : "ready",
      queueDir: "project-state/backup-jobs",
      running: jobs.filter((job) => job.queueStatus === "running").length,
      queued: jobs.filter((job) => job.queueStatus === "queued").length,
      failed: jobs.filter((job) => job.queueStatus === "failed").length,
      done: jobs.filter((job) => job.queueStatus === "done").length,
    },
    jobs,
    localCoverage: localFamiliesPassed ? "covered" : "incomplete",
    latest: records.slice(0, 5),
  });
}

function applicationBackupInventory(context, project) {
  const databases = projectBackupDatabases(context, project);
  const storage = projectStorage(context, project);
  const resources = applicationBackupResources(context, project);
  const sourcePath = applicationSourceBackupPath(project);
  const sourceStats = readBackupDirectoryStats(sourcePath);
  const manifests = applicationBackupManifests(project);
  const artifacts = manifests.flatMap((manifest) => manifest.artifacts);
  const restoreOptions = applicationBackupRestoreOptions(manifests);
  const allSizeBytes = sourceStats.sizeBytes + artifacts.reduce((total, artifact) => total + Number(artifact.sizeBytes || 0), 0);
  const latest = manifests[0] || null;
  const jobs = (context.backups?.jobs || []).filter((job) => job.scope?.kind === "application" && job.scope?.id === project.slug).slice(0, 5);
  const records = (context.backupRecords || []).filter((record) => record.scope === applicationBackupScope(project.slug)).slice(0, 5);
  const hasBackupFiles = manifests.length > 0;
  return sanitizeEvent({
    projectId: project.slug,
    projectName: project.name,
    runtime: project.runtime,
    sourcePath,
    sourceFileCount: sourceStats.fileCount,
    sourceDirectoryCount: sourceStats.directoryCount,
    artifactCount: artifacts.length,
    fileCount: sourceStats.fileCount + artifacts.length,
    sizeBytes: allSizeBytes,
    sizeLabel: usageBytesLabel(allSizeBytes),
    latestName: latest?.id || "",
    latestPath: latest?.path || "",
    latestModifiedAt: latest?.createdAt ? italianDateTimeLabel(latest.createdAt) : "",
    databaseCount: databases.length,
    storageCount: storage.buckets.length + storage.webspaces.length,
    resourceCount: resources.length,
    restoreOptions,
    jobs,
    records,
    status: hasBackupFiles ? "available" : resources.length ? "ready" : "missing",
    statusLabel: hasBackupFiles ? "Disponibile" : resources.length ? "Pronto" : "Non configurato",
  });
}

function applicationBackupScope(projectId) {
  return `app-${sanitizeIdentifier(projectId)}`;
}

function applicationBackupMode(value) {
  return choice(String(value || "all").toLowerCase(), ["all", "source", "database"], "application backup mode");
}

function applicationRestoreMode(value) {
  return choice(String(value || "all").toLowerCase(), ["all", "source", "database"], "application restore mode");
}

function applicationRestoreModeLabel(value) {
  const labels = {
    all: "tutto",
    source: "solo sorgenti",
    database: "solo database",
  };
  return labels[applicationRestoreMode(value)] || "tutto";
}

function projectBackupDatabases(context, projectOrId) {
  const project = resolveContextProject(context, projectOrId);
  if (!project) return [];
  const identities = projectIdentitySet(project);
  return context.databases.filter((database) => identities.has(database.projectId)
    || databaseLinkedApps(database).some((linkedId) => identities.has(linkedId)));
}

function applicationBackupResources(context, projectOrId, mode = "all") {
  const project = resolveContextProject(context, projectOrId);
  if (!project) return [];
  const backupMode = applicationBackupMode(mode);
  const resources = [];
  if ((backupMode === "all" || backupMode === "source") && project.filesystemExists !== false) {
    resources.push({
      id: backupResourceId("source", project.slug),
      externalId: project.slug,
      kind: "source",
      projectId: project.slug,
      name: project.slug,
      sourceDirectory: path.basename(String(project.relativePath || project.slug)),
    });
  }
  if (backupMode === "all" || backupMode === "database") {
    for (const database of projectBackupDatabases(context, project)) {
      resources.push({
        id: backupResourceId("database", database.id),
        externalId: database.id,
        kind: "database",
        projectId: project.slug,
        name: database.name,
        engine: database.engine,
      });
    }
  }
  return resources;
}

function readBackupManifests() {
  const root = path.resolve(backupRoot);
  const directory = path.join(root, "manifests");
  if (!existsSync(directory)) return [];
  const manifests = [];
  for (const name of readdirSync(directory).filter((item) => item.endsWith(".json")).slice(0, 500)) {
    const target = path.resolve(directory, name);
    if (!target.startsWith(`${directory}${path.sep}`)) continue;
    try {
      const parsed = parseBackupManifestDocument(JSON.parse(readFileSync(target, "utf8")));
      if (!parsed.signature || parsed.signature.digest !== backupDocumentDigest(parsed)) continue;
      const artifacts = parsed.artifacts.map((artifact) => {
        const artifactPath = path.resolve(root, artifact.path);
        if (!artifactPath.startsWith(`${root}${path.sep}`) || !existsSync(artifactPath)) return null;
        const stat = statSync(artifactPath);
        if (!stat.isFile() || stat.size !== artifact.sizeBytes) return null;
        return {
          ...artifact,
          name: path.basename(artifact.path),
          sizeLabel: usageBytesLabel(artifact.sizeBytes),
          modifiedAt: italianDateTimeLabel(stat.mtime),
          mtimeMs: stat.mtimeMs,
        };
      }).filter(Boolean);
      if (artifacts.length !== parsed.artifacts.length) continue;
      manifests.push({
        ...parsed,
        path: joinRelativePath("manifests", name),
        artifacts,
      });
    } catch {
      // Invalid, unsigned or incomplete manifests never enter the application inventory.
    }
  }
  return manifests.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
}

function applicationBackupManifests(project) {
  return readBackupManifests().filter((manifest) => manifest.scope.kind === "application" && manifest.scope.id === project.slug);
}

function applicationBackupRestoreOptions(manifests) {
  return (manifests || []).map((manifest) => ({
    name: manifest.id,
    path: manifest.path,
    label: `${italianDateTimeLabel(manifest.createdAt)} - ${manifest.artifacts.length} risorse`,
    modifiedAt: italianDateTimeLabel(manifest.createdAt),
    sizeLabel: usageBytesLabel(manifest.artifacts.reduce((total, artifact) => total + artifact.sizeBytes, 0)),
    kind: "Manifest firmato",
    manifest,
  }));
}

function applicationSourceBackupPath(project) {
  return joinRelativePath("applications", sanitizeIdentifier(project.slug || project.id || project.name));
}

function safeReadBackupFiles(requestedPath = "") {
  try {
    return readBackupFiles(requestedPath);
  } catch (error) {
    return sanitizeEvent({
      available: false,
      root: "backups/",
      path: "",
      parentPath: "",
      entries: [],
      sizeBytes: 0,
      fileCount: 0,
      directoryCount: 0,
      message: error instanceof Error ? error.message : "Backup non disponibili.",
    });
  }
}

function readBackupFamily(spec) {
  const report = latestDocumentedReport("backups", spec.reportPrefix);
  const payload = report?.payload || {};
  const directory = readBackupDirectoryStats(spec.id);
  const artifact = latestBackupArtifact(spec.id);
  const reportStatus = String(payload.status || "").toLowerCase();
  const success = reportStatus === "success" && Boolean(payload.artifactSha256 || payload.artifactPath || artifact);
  return sanitizeEvent({
    id: spec.id,
    label: spec.label,
    command: spec.command,
    restoreCommand: spec.restoreCommand,
    status: success ? "success" : report ? "needs-work" : artifact ? "local-file" : "missing",
    reportPath: report?.reportPath || "",
    reportAgeLabel: report ? relativeTimeLabel(payload.generatedAt || payload.finishedAt) : "",
    integrityVerified: payload.integrityVerified === true,
    artifactName: payload.artifactName || artifact?.name || "",
    artifactPath: backupArtifactDisplayPath(payload.artifactPath || artifact?.path || ""),
    artifactSizeBytes: Number(payload.artifactSizeBytes || artifact?.sizeBytes || 0),
    artifactSizeLabel: usageBytesLabel(Number(payload.artifactSizeBytes || artifact?.sizeBytes || 0)),
    latestModifiedAt: artifact?.modifiedAt || payload.finishedAt || payload.generatedAt || "",
    fileCount: directory.fileCount,
    directoryCount: directory.directoryCount,
    totalSizeBytes: directory.sizeBytes,
    totalSizeLabel: usageBytesLabel(directory.sizeBytes),
  });
}

function backupRootSummary(files) {
  const disk = backupDiskSummary();
  return {
    path: "backups/",
    available: files.available,
    sizeBytes: files.sizeBytes || 0,
    sizeLabel: usageBytesLabel(files.sizeBytes || 0),
    fileCount: files.fileCount || 0,
    directoryCount: files.directoryCount || 0,
    diskFreeLabel: disk.available ? usageBytesLabel(disk.freeBytes) : "n.d.",
    diskTotalLabel: disk.available ? usageBytesLabel(disk.totalBytes) : "n.d.",
  };
}

function readBackupFiles(requestedPath = "") {
  const root = path.resolve(backupRoot);
  if (!existsSync(root)) {
    return sanitizeEvent({
      available: false,
      root: "backups/",
      path: "",
      parentPath: "",
      entries: [],
      sizeBytes: 0,
      fileCount: 0,
      directoryCount: 0,
      message: "La directory backup non e' montata nel Control Center.",
    });
  }
  const realRoot = backupRealpath(root);
  const relativePath = safeRelativeBackupPath(requestedPath || "");
  const target = path.resolve(realRoot, relativePath);
  if (!(target === realRoot || target.startsWith(`${realRoot}${path.sep}`))) {
    throw new ValidationError("Percorso backup non valido.");
  }
  if (!existsSync(target)) throw new ValidationError("Percorso backup non trovato.");
  assertNoBackupPathSymlink(realRoot, relativePath);
  const stat = lstatSync(target);
  if (stat.isSymbolicLink()) throw new ValidationError("I symlink non vengono aperti dal Control Center.");
  const totals = directorySizeSummary(realRoot, 5000);
  if (!stat.isDirectory()) {
    return sanitizeEvent({
      available: true,
      root: "backups/",
      path: relativePath,
      parentPath: parentRelativeBackupPath(relativePath),
      entries: [backupFileEntryRecord(target, path.basename(target), relativePath)].filter(Boolean),
      sizeBytes: totals.sizeBytes,
      fileCount: totals.fileCount,
      directoryCount: totals.directoryCount,
      message: "",
    });
  }
  const entries = readdirSync(target, { withFileTypes: true })
    .filter((entry) => !entry.name.startsWith("."))
    .slice(0, 300)
    .map((entry) => backupFileEntryRecord(path.join(target, entry.name), entry.name, joinRelativePath(relativePath, entry.name)))
    .filter(Boolean)
    .sort((a, b) => (a.type === b.type ? String(b.modifiedAt || "").localeCompare(String(a.modifiedAt || "")) || a.name.localeCompare(b.name) : a.type === "directory" ? -1 : 1));
  return sanitizeEvent({
    available: true,
    root: "backups/",
    path: relativePath,
    parentPath: parentRelativeBackupPath(relativePath),
    entries,
    sizeBytes: totals.sizeBytes,
    fileCount: totals.fileCount,
    directoryCount: totals.directoryCount,
    message: "",
  });
}

function readBackupDirectoryStats(familyId) {
  const root = path.resolve(backupRoot);
  const familyPath = path.resolve(root, safeRelativeBackupPath(familyId));
  if (!existsSync(root) || !existsSync(familyPath) || !(familyPath === root || familyPath.startsWith(`${root}${path.sep}`))) {
    return { sizeBytes: 0, fileCount: 0, directoryCount: 0 };
  }
  return directorySizeSummary(familyPath, 3000);
}

function latestBackupArtifact(familyId) {
  return backupArtifactEntriesRecursive(familyId)[0] || null;
}

function backupArtifactEntriesRecursive(relativeDir, limit = 1200) {
  const root = path.resolve(backupRoot);
  const familyPath = path.resolve(root, safeRelativeBackupPath(relativeDir));
  if (!existsSync(root) || !existsSync(familyPath) || !(familyPath === root || familyPath.startsWith(`${root}${path.sep}`))) return [];
  const entries = [];
  const stack = [familyPath];
  let visited = 0;
  try {
    while (stack.length && visited < limit) {
      const current = stack.pop();
      visited += 1;
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        for (const entry of readdirSync(current, { withFileTypes: true })) {
          if (!entry.name.startsWith(".")) stack.push(path.join(current, entry.name));
        }
        continue;
      }
      if (!stat.isFile() || !backupDataArtifactName(path.basename(current))) continue;
      const relativePath = path.relative(root, current).replaceAll("\\", "/");
      const record = backupFileEntryRecord(current, path.basename(current), relativePath);
      if (record) entries.push({ ...record, mtimeMs: stat.mtimeMs });
    }
  } catch {
    return [];
  }
  return entries.sort((a, b) => Number(b.mtimeMs || 0) - Number(a.mtimeMs || 0));
}

function backupDataArtifactName(name) {
  return /\.(dump|sql\.gz|tar\.gz)$/i.test(String(name || ""));
}

function backupFileEntryRecord(filePath, name, relativePath) {
  try {
    const stat = lstatSync(filePath);
    const isSymlink = stat.isSymbolicLink();
    const isDirectory = stat.isDirectory();
    return {
      name: sanitizeBackupDisplay(name),
      path: safeRelativeBackupPath(relativePath),
      type: isSymlink ? "symlink" : isDirectory ? "directory" : "file",
      sizeBytes: isDirectory || isSymlink ? 0 : stat.size,
      sizeLabel: isDirectory ? "" : usageBytesLabel(stat.size),
      modifiedAt: italianDateTimeLabel(stat.mtime),
      browsable: isDirectory && !isSymlink,
      removable: !isDirectory && !isSymlink && backupFileDeleteAllowed(relativePath),
    };
  } catch {
    return null;
  }
}

function directorySizeSummary(root, limit = 3000) {
  const summary = { sizeBytes: 0, fileCount: 0, directoryCount: 0 };
  const stack = [root];
  let visited = 0;
  while (stack.length && visited < limit) {
    const current = stack.pop();
    visited += 1;
    let stat;
    try {
      stat = lstatSync(current);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      summary.directoryCount += 1;
      try {
        for (const entry of readdirSync(current)) {
          if (!entry.startsWith(".")) stack.push(path.join(current, entry));
        }
      } catch {
        // Ignore directories that become unavailable while scanning.
      }
      continue;
    }
    if (stat.isFile()) {
      summary.fileCount += 1;
      summary.sizeBytes += stat.size;
    }
  }
  return summary;
}

function backupDiskSummary() {
  try {
    const root = existsSync(backupRoot) ? backupRoot : path.dirname(backupRoot);
    const stat = statfsSync(root);
    return {
      available: true,
      freeBytes: Number(stat.bavail || stat.bfree || 0) * Number(stat.bsize || 0),
      totalBytes: Number(stat.blocks || 0) * Number(stat.bsize || 0),
    };
  } catch {
    return { available: false, freeBytes: 0, totalBytes: 0 };
  }
}

function safeRelativeBackupPath(value) {
  const normalized = String(value || "").replaceAll("\\", "/").replace(/^\/+|\/+$/g, "");
  if (!normalized) return "";
  if (normalized.includes("..") || /^[A-Za-z]:/.test(normalized)) throw new ValidationError("Percorso backup non valido.");
  if (!/^[A-Za-z0-9._/@ -]+$/.test(normalized)) throw new ValidationError("Percorso backup non valido.");
  return normalized;
}

function parentRelativeBackupPath(value) {
  const normalized = safeRelativeBackupPath(value);
  if (!normalized) return "";
  const parent = path.posix.dirname(normalized.replaceAll("\\", "/"));
  return parent === "." ? "" : parent;
}

function assertNoBackupPathSymlink(root, relativePath) {
  const parts = safeRelativeBackupPath(relativePath).split("/").filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = path.join(current, part);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) throw new ValidationError("I symlink non vengono aperti dal Control Center.");
  }
}

function backupRealpath(value) {
  try {
    return realpathSync(value);
  } catch {
    throw new ValidationError("Directory backup non trovata.");
  }
}

function backupArtifactDisplayPath(value) {
  const raw = String(value || "");
  if (!raw) return "";
  const index = raw.indexOf("/backups/");
  return index >= 0 ? raw.slice(index + 1) : safeRelativeBackupPath(raw.replace(path.resolve(backupRoot), "").replace(/^\/+/, ""));
}

function sanitizeBackupDisplay(value) {
  return String(value || "").trim().replace(/[^a-zA-Z0-9._/@: -]+/g, "-").slice(0, 180) || "unknown";
}

function backupFileDeleteAllowed(value) {
  const pathValue = String(value || "");
  return /\.(dump|sql\.gz|tar\.gz|sha256|sig\.json)$/i.test(pathValue);
}

function backupPreviewAllowed(value) {
  const pathValue = String(value || "");
  return /\.(json|md|txt|sha256|sig\.json|sql|sql\.gz|dump|tar\.gz)$/i.test(pathValue);
}

function readBackupPreview(requestedPath = "") {
  const relativePath = safeRelativeBackupPath(requestedPath || "");
  if (!relativePath) throw new ValidationError("Percorso backup richiesto.");
  if (!backupPreviewAllowed(relativePath)) throw new ValidationError("Tipo file backup non supportato per anteprima.");
  const root = backupRealpath(path.resolve(backupRoot));
  const target = path.resolve(root, relativePath);
  if (!(target === root || target.startsWith(`${root}${path.sep}`))) throw new ValidationError("Percorso backup non valido.");
  if (!existsSync(target)) throw new ValidationError("File backup non trovato.");
  assertNoBackupPathSymlink(root, relativePath);
  const stat = lstatSync(target);
  if (stat.isDirectory() || stat.isSymbolicLink()) throw new ValidationError("Anteprima disponibile solo per file reali.");
  const ext = relativePath.toLowerCase();
  const result = {
    path: relativePath,
    name: path.basename(relativePath),
    type: backupPreviewType(ext),
    sizeBytes: stat.size,
    sizeLabel: usageBytesLabel(stat.size),
    modifiedAt: italianDateTimeLabel(stat.mtime),
    mode: "metadata-only",
    content: "",
    linesRedacted: 0,
    message: "",
  };
  if (ext.endsWith(".dump") || ext.endsWith(".sql.gz") || ext.endsWith(".sql")) {
    return sanitizeEvent({
      ...result,
      mode: "metadata-only",
      content: "",
      message: "Dump database: il contenuto non viene letto o mostrato nel browser. Usa un restore drill isolato per verificarlo.",
    });
  }
  if (ext.endsWith(".tar.gz")) {
    return sanitizeEvent({
      ...result,
      content: "",
      message: "Archivio tar.gz: contenuto raw non mostrato nel browser. L'integrita' e il restore sono verificati dai report.",
    });
  }
  const preview = safeBackupPreview(target, relativePath);
  return sanitizeEvent({
    ...result,
    mode: preview.mode,
    content: preview.content,
    linesRedacted: 0,
    message: preview.message,
  });
}

function backupPreviewType(ext) {
  if (ext.endsWith(".sql.gz")) return "sql-gzip";
  if (ext.endsWith(".sql")) return "sql";
  if (ext.endsWith(".sig.json")) return "signature-json";
  if (ext.endsWith(".sha256")) return "sha256";
  if (ext.endsWith(".json")) return "json";
  if (ext.endsWith(".md")) return "markdown";
  if (ext.endsWith(".dump")) return "postgres-custom-dump";
  if (ext.endsWith(".tar.gz")) return "tar-gzip";
  return "text";
}

function uniqueBackupResources(resources) {
  const seen = new Set();
  return resources.filter((resource) => {
    if (seen.has(resource.id)) return false;
    seen.add(resource.id);
    return true;
  });
}

function platformBackupResources(context, requestedScope) {
  const resources = [];
  if (requestedScope === "all" || requestedScope === "applications") {
    for (const project of context.projects) resources.push(...applicationBackupResources(context, project, "source"));
  }
  if (requestedScope === "all" || requestedScope === "postgres" || requestedScope === "mariadb") {
    for (const database of context.databases) {
      if (!database.projectId || (requestedScope !== "all" && database.engine !== requestedScope)) continue;
      resources.push({
        id: backupResourceId("database", database.id),
        externalId: database.id,
        kind: "database",
        projectId: database.projectId,
        name: database.name,
        engine: database.engine,
      });
    }
  }
  return uniqueBackupResources(resources);
}

function resolveBackupRunRequest(payload, context) {
  const requestedScope = sanitizeIdentifier(payload.scope || "all") || "all";
  if (requestedScope === "application" || requestedScope.startsWith("app-")) {
    const projectId = requestedScope.startsWith("app-")
      ? requestedScope.replace(/^app-/, "")
      : sanitizeIdentifier(payload.projectId || payload.applicationId || payload.appId || "");
    const project = resolveContextProject(context, projectId);
    if (!project) throw new ValidationError("Applicazione backup non trovata.");
    const mode = applicationBackupMode(payload.backupMode || payload.backupContents || "all");
    const resources = applicationBackupResources(context, project, mode);
    if (!resources.length) throw new ValidationError("Questa applicazione non ha risorse backup eseguibili con identita' esatta.");
    return {
      scopeLabel: applicationBackupScope(project.slug),
      scope: { kind: "application", id: project.slug },
      resources,
      project,
      mode,
    };
  }
  if (!["all", "applications", "postgres", "mariadb"].includes(requestedScope)) {
    throw new ValidationError("Questo ambito richiede il catalogo completo T07 e non viene accodato come job parziale.");
  }
  const resources = platformBackupResources(context, requestedScope);
  if (!resources.length) throw new ValidationError("Nessuna risorsa con ownership esatta per questo ambito.");
  return {
    scopeLabel: requestedScope,
    scope: { kind: "platform", id: "platform" },
    resources,
    project: null,
    mode: requestedScope,
  };
}

function resolveBackupRestoreRequest(payload, context) {
  const requestedScope = sanitizeIdentifier(payload.scope || "all") || "all";
  if (requestedScope === "application" || requestedScope.startsWith("app-")) {
    const projectId = requestedScope.startsWith("app-")
      ? requestedScope.replace(/^app-/, "")
      : sanitizeIdentifier(payload.projectId || payload.applicationId || payload.appId || "");
    const project = resolveContextProject(context, projectId);
    if (!project) throw new ValidationError("Applicazione backup non trovata.");
    const options = applicationBackupRestoreOptions(applicationBackupManifests(project));
    if (!options.length) throw new ValidationError("Questa applicazione non ha backup ripristinabili.");
    const requestedRef = String(payload.backupRef || payload.backupId || "latest") === "latest"
      ? options[0].path
      : safeRelativeBackupPath(payload.backupRef || payload.backupId || "");
    const selected = options.find((option) => option.path === requestedRef);
    if (!selected) throw new ValidationError("Backup applicazione non trovato o non ripristinabile.");
    const mode = applicationRestoreMode(payload.restoreMode || payload.restoreContents || "all");
    const resources = selected.manifest.resources.filter((resource) => mode === "all"
      || (mode === "source" && resource.kind === "source")
      || (mode === "database" && resource.kind === "database"));
    if (!resources.length) throw new ValidationError("Il manifest selezionato non contiene risorse per la modalita' richiesta.");
    return {
      scopeLabel: applicationBackupScope(project.slug),
      scope: { kind: "application", id: project.slug },
      backupRef: selected.path,
      resources,
      project,
      selected,
      mode,
    };
  }
  const manifests = readBackupManifests().filter((manifest) => manifest.scope.kind === "platform");
  const requestedRef = String(payload.backupRef || payload.backupId || "latest") === "latest"
    ? manifests[0]?.path
    : safeRelativeBackupPath(payload.backupRef || payload.backupId || "");
  const selected = manifests.find((manifest) => manifest.path === requestedRef);
  if (!selected) throw new ValidationError("Manifest platform firmato non trovato.");
  return {
    scopeLabel: requestedScope,
    scope: { kind: "platform", id: "platform" },
    backupRef: selected.path,
    resources: selected.resources,
    project: null,
    selected: { manifest: selected, path: selected.path, name: selected.id },
    mode: "all",
  };
}

function queueBackupRun(payload, context) {
  const { scopeLabel, scope, resources, project, mode } = resolveBackupRunRequest(payload, context);
  const job = createBackupJob({ operation: "backup", scope, resources, context });
  appendAudit({ action: "backup.run.queue", target: scopeLabel, environment: context.environment, risk: "medium", result: "accepted", dryRun: false, summary: project ? `Typed application backup queued for ${project.slug} (${mode || "all"}).` : "Typed platform backup queued for backup scheduler execution." });
  const operation = operationPlan("backup.run", context.environment, false, ["write versioned typed job", "backup scheduler validates schema", "execute exact resource IDs", "write signed manifest"], {
    scope: scopeLabel,
    projectId: project?.slug || "",
    backupMode: mode || "",
    jobId: job.id,
    executor: "enterprise-backup-scheduler",
    resourceIds: resources.map((resource) => resource.id),
    productionEvidence: false,
  });
  const backup = backupRecord({
    operationId: operation.id,
    jobId: job.id,
    action: "backup",
    scope: scopeLabel,
    environment: context.environment,
    status: "queued",
    dryRun: false,
    resultSummary: project ? `Backup applicazione ${project.name} accodato al backup scheduler (${mode || "all"}).` : "Backup queued for backup scheduler execution.",
  });
  appendBackupRecord(backup);
  return { ...operation, backup, job };
}

function queueRestoreDrill(payload, context) {
  const { scopeLabel, scope, backupRef, resources, project, selected, mode } = resolveBackupRestoreRequest(payload, context);
  const job = createBackupJob({ operation: "restore-drill", scope, sourceManifestPath: backupRef, resources, context });
  appendAudit({ action: "restore.queue", target: scopeLabel, environment: context.environment, risk: "high", result: "accepted", dryRun: false, summary: project ? `Exact-manifest restore drill queued for ${project.slug} (${applicationRestoreModeLabel(mode)}).` : "Exact-manifest restore drill queued for backup scheduler execution." });
  const operation = operationPlan("restore.queue", context.environment, false, ["validate signed source manifest", "verify exact artifact signatures", "restore only into disposable targets", "write drill evidence"], {
    scope: scopeLabel,
    backupRef,
    projectId: project?.slug || "",
    restoreMode: mode || "",
    jobId: job.id,
    executor: "enterprise-backup-scheduler",
    resourceIds: resources.map((resource) => resource.id),
    dataChanged: false,
    productionEvidence: false,
  });
  const backup = backupRecord({
    operationId: operation.id,
    jobId: job.id,
    action: "restore-drill",
    scope: scopeLabel,
    environment: context.environment,
    status: "queued",
    dryRun: false,
    backupRef,
    resultSummary: project ? `Restore drill applicazione ${project.name} accodato al backup scheduler (${applicationRestoreModeLabel(mode)}).` : "Restore drill queued for backup scheduler execution.",
  });
  appendBackupRecord(backup);
  return { ...operation, backup, job, selectedManifestId: selected?.manifest?.id || selected?.name || "" };
}

function createBackupJob({ operation, scope, sourceManifestPath = "", resources, context }) {
  const now = new Date().toISOString();
  const identity = requestIdentity.getStore();
  const job = createBackupJobDocument({
    id: rid(),
    operation,
    scope,
    resources,
    requestedBy: identity?.subject || "control-center",
    environment: context.environment,
    createdAt: now,
    sourceManifestPath,
  });
  const queuedDir = path.join(backupJobsDir, "queued");
  mkdirSync(queuedDir, { recursive: true, mode: 0o700 });
  writePrivateJsonAtomic(path.join(queuedDir, `${job.id}.json`), job);
  return job;
}

function readBackupJobs() {
  const jobs = [];
  for (const status of ["running", "queued", "failed", "done"]) {
    const dir = path.join(backupJobsDir, status);
    if (!existsSync(dir)) continue;
    try {
      for (const name of readdirSync(dir).filter((item) => item.endsWith(".json")).slice(0, 200)) {
        try {
          const target = path.resolve(dir, name);
          if (!target.startsWith(`${path.resolve(dir)}${path.sep}`)) continue;
          const parsed = parseBackupJobDocument(JSON.parse(readFileSync(target, "utf8")));
          if (parsed.status !== status) continue;
          jobs.push(sanitizeEvent({ ...parsed, queueStatus: status }));
        } catch {
          // Ignore only the invalid job; keep the remaining queue inventory available.
        }
      }
    } catch {
      // Keep the backup page available if the queue directory is unreadable.
    }
  }
  return jobs
    .sort((a, b) => String(b.updatedAt || b.createdAt || "").localeCompare(String(a.updatedAt || a.createdAt || "")))
    .slice(0, 80);
}

function renderControlCenter(context, params) {
  const sections = operationsPortalSections();
  const requestedSection = params.get("section") || "status";
  const section = sections.some((item) => item.id === requestedSection) ? requestedSection : "status";
  const selectedProject = context.projects.some((project) => project.slug === params.get("project")) ? params.get("project") : context.projects[0]?.slug || "";
  const currentProject = context.projects.find((project) => project.slug === selectedProject) || null;
  const activeProject = section === "projects" && params.has("project") ? currentProject : null;
  const title = sections.find((item) => item.id === section)?.label || "Status";
  const body = renderOperationsSection(section, context, params, currentProject);
  const hidePageHead = Boolean(activeProject);
  const pageHint = operationPageHint(section, context);
  const pageLabel = hidePageHead ? `aria-label="${escapeHtml(title)}"` : 'aria-labelledby="control-page-title"';
  const pageHead = hidePageHead ? "" : `<div class="ops-page-head">
        <div>
          <h1 id="control-page-title">${escapeHtml(title)}</h1>
          ${pageHint ? `<span>${escapeHtml(pageHint)}</span>` : ""}
        </div>
      </div>`;

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
      ${renderOperationsNav(sections, section, context, activeProject, params)}
      ${controlAuth.enabled ? '<form action="/logout" method="post" class="ops-logout-form"><button class="ops-icon-link" type="submit" aria-label="Logout">Logout</button></form>' : ""}
    </aside>
    <section class="ops-page" ${pageLabel}>
      ${pageHead}
      ${body}
    </section>
  </div>
</main>
</body>
  </html>`;
}

function renderOperationsNav(sections, section, context, activeProject, params = new URLSearchParams()) {
  const visibleSections = sections.filter((item) => !item.hidden);
  return `<nav class="ops-nav" aria-label="Sezioni portal">
    <span class="ops-nav-pill" aria-hidden="true"></span>
    ${visibleSections.map((item) => renderOperationsNavGroup(item, section, context, activeProject, params)).join("")}
  </nav>`;
}

function renderOperationsNavGroup(item, section, context, activeProject, params = new URLSearchParams()) {
  const currentSection = item.id === section;
  const children = operationsNavChildren(item.id, context, activeProject, params, currentSection);
  const expanded = currentSection;
  const childActive = children.some((child) => child.active);
  const locked = expanded && childActive;
  const panelId = `ops-nav-panel-${item.id}`;
  const hasChildren = children.length > 0;
  const toggleLabel = locked ? `Sezione attuale: ${item.label}` : expanded ? `Chiudi ${item.label}` : `Apri ${item.label}`;
  return `<div class="ops-nav-group ${expanded ? "expanded" : ""}" data-ops-nav-group="${escapeHtml(item.id)}" data-ops-nav-expanded="${expanded ? "true" : "false"}" data-ops-nav-has-active-child="${childActive ? "true" : "false"}" data-ops-nav-locked="${locked ? "true" : "false"}"${hasChildren ? ' data-ops-nav-collapsible="true"' : ""}>
    <div class="ops-nav-row">
      <button class="ops-nav-main" type="button" data-ops-nav-toggle aria-label="${escapeHtml(toggleLabel)}" aria-expanded="${expanded ? "true" : "false"}" aria-controls="${escapeHtml(panelId)}"${locked ? ' aria-disabled="true"' : ""}>
        ${controlIcon(item.icon)}
        <span class="ops-nav-main-label">${escapeHtml(item.label)}</span>
        <span class="ops-nav-chevron" aria-hidden="true">${controlIcon("chevron-down")}</span>
      </button>
    </div>
    ${children.length ? `<div class="ops-nav-sublist" id="${escapeHtml(panelId)}" aria-hidden="${expanded ? "false" : "true"}">
      ${children.map((child) => renderOperationsNavChild(child)).join("")}
    </div>` : ""}
  </div>`;
}

function renderOperationsNavChild(child) {
  const tone = child.tone ? ` ${child.tone}` : "";
  const state = child.state ? ` ${child.state}` : "";
  const statusAttrs = child.statusCategory
    ? ` data-status-category-card="${escapeHtml(child.statusCategory)}" data-status-category-state="${escapeHtml(child.state || "")}"`
    : "";
  return `<a class="ops-nav-subitem${child.active ? " active" : ""}${escapeHtml(state)}" ${child.active ? 'aria-current="page"' : ""}${statusAttrs} href="${escapeHtml(child.href)}">
    <span class="ops-nav-subdot${escapeHtml(tone)}" aria-hidden="true"></span>
    <span>${escapeHtml(child.label)}</span>
  </a>`;
}

function operationsNavChildren(section, context, activeProject, params = new URLSearchParams(), currentSection = false) {
  if (section === "status") {
    return statusNavChildren(context, params, currentSection);
  }
  if (section === "projects") {
    return [
      {
        active: currentSection && !activeProject,
        href: "/?section=projects",
        label: "Tutte",
      },
      ...sortedOpsProjects(context.projects).map((project) => {
        const state = projectOpsState(project);
        return {
          active: activeProject?.slug === project.slug,
          href: `/?section=projects&project=${encodeURIComponent(project.slug)}`,
          label: project.name,
          tone: projectStatusTone(project, state),
        };
      }),
    ];
  }
  if (section === "vault") {
    return [
      {
        active: currentSection,
        href: "/?section=vault",
        label: "Secret",
        tone: context.vaultItems?.length ? "good" : "warn",
      },
    ];
  }
  return [];
}

function statusNavChildren(context, params = new URLSearchParams(), currentSection = false) {
  const groups = groupStatusRowsByCategory(statusRowsForContext(context));
  const activeId = selectedStatusGroup(groups, params).meta.id;
  return groups.map((group) => {
    const counts = statusCategoryCounts(group.rows);
    const blocked = counts.open > 0;
    return {
      active: currentSection && group.meta.id === activeId,
      href: `/?section=status&statusCategory=${encodeURIComponent(group.meta.id)}#status-run`,
      label: group.meta.label,
      state: blocked ? "blocked" : "passed",
      statusCategory: group.meta.id,
      tone: blocked ? "bad" : "good",
    };
  });
}

function operationsPortalSections() {
  return [
    { id: "status", label: "Stato", icon: "overview" },
    { id: "projects", label: "Applicazioni", icon: "projects" },
    { id: "vault", label: "Vault", icon: "shield" },
    { id: "files", label: "File", icon: "file", hidden: true },
    { id: "databases", label: "Database", icon: "databases", hidden: true },
  ];
}

function operationPageHint(section, context) {
  const hints = {
    status: "",
    projects: "Elenco applicazioni con host, runtime e dettaglio operativo.",
    vault: "Secret cifrati: puoi aggiungerli e rimuoverli senza mostrare valori in chiaro.",
    files: "Inventario file applicazione in sola lettura.",
    databases: "Database collegati alle applicazioni e azioni metadata.",
  };
  return hints[section] || "";
}

function renderOperationsSection(section, context, params, currentProject) {
  if (section === "projects") return renderOpsProjects(context, params);
  if (section === "vault") return renderOpsVault(context);
  if (section === "files") return renderOpsFiles(context, params, currentProject);
  if (section === "databases") return renderOpsDatabases(context, currentProject);
  return renderOpsStatus(context, params);
}

function renderOpsStatus(context, params = new URLSearchParams()) {
  const report = context.goNoGo;
  const isGo = report.status === "go";
  const status = isGo ? "GO LIVE" : "NO GO LIVE";
  const rows = statusRowsForContext(context);
  const passedRows = rows.filter((row) => row.status === "passed");
  const notPassedRows = rows.filter((row) => row.status !== "passed");
  const groups = groupStatusRowsByCategory(rows);
  const selectedGroup = selectedStatusGroup(groups, params);
  const selectedCounts = statusCategoryCounts(selectedGroup.rows);
  const lastRun = context.statusRun;
  const score = rows.length ? Math.round((passedRows.length / rows.length) * 100) : 0;
  const nextStep = isGo
    ? "Nessun blocco aperto."
    : notPassedRows.length
      ? `${notPassedRows.length} controlli aperti.`
      : "Report da aggiornare.";
  const selectedRunSteps = statusRunStepDefinitionsForRows(selectedGroup.rows, selectedGroup.meta.id);
  return `<section class="ops-section ops-status-redesign" data-status-runner data-status-step-delay-ms="${escapeHtml(String(statusRunStepDelayMs))}">
    <div class="ops-status-overview ${isGo ? "good" : "bad"}" id="status-run">
      <span class="ops-status-overview-icon" aria-hidden="true">${controlIcon(isGo ? "rocket" : "shield")}</span>
      <div class="ops-status-overview-main">
        <h2>${escapeHtml(status)}</h2>
        <p>${escapeHtml(nextStep)}</p>
      </div>
      <div class="ops-status-overview-score" aria-label="Avanzamento controlli">
        <strong>${escapeHtml(String(score))}%</strong>
        <span>${escapeHtml(`${passedRows.length}/${rows.length} superati`)}</span>
        <div class="ops-status-mini-progress" aria-hidden="true"><i style="width: ${escapeHtml(String(score))}%"></i></div>
      </div>
      <form method="post" action="/actions/status-check" data-status-run-form>
        <input type="hidden" name="scope" value="all">
        <button class="ops-button primary" type="submit" data-status-run-button>${controlIcon("play")} Avvia test reali</button>
      </form>
    </div>

    <div class="ops-status-workspace">
      <div class="ops-status-main">
        <details class="ops-status-runner" data-status-run-console>
          <summary class="ops-status-runner-head">
            <div>
              <h2>Esecuzione test</h2>
              <p data-status-progress-label>${escapeHtml(lastRun ? `Ultimo run: ${lastRun.generatedAt || "n.d."}` : "Pronto per partire.")}</p>
            </div>
            <span class="ops-status-run-state" data-status-run-state>${escapeHtml(lastRun ? friendlyGoNoGoStatus(lastRun.status) : "In attesa")}</span>
          </summary>
          <div class="ops-status-runner-body">
            <div class="ops-status-progress" aria-hidden="true"><span data-status-progress-bar style="width: 0%"></span></div>
            ${renderStatusRunSteps(lastRun, selectedRunSteps)}
          </div>
        </details>

        <div class="ops-panel ops-status-results" data-status-section-detail="${escapeHtml(selectedGroup.meta.id)}">
          <div class="ops-status-results-head">
            <div>
              <h2>${escapeHtml(selectedGroup.meta.label)}</h2>
              <p>${escapeHtml(`${selectedCounts.total} controlli: ${selectedCounts.open} aperti, ${selectedCounts.passed} superati.`)}</p>
            </div>
            <form method="post" action="/actions/status-check" data-status-run-form>
              <input type="hidden" name="scope" value="category">
              <input type="hidden" name="category" value="${escapeHtml(selectedGroup.meta.id)}">
              <button class="ops-button secondary" type="submit" data-status-run-button>${controlIcon("play")} Esegui sezione</button>
            </form>
          </div>
          ${renderStatusCategoryTable(selectedGroup.meta, selectedGroup.rows, { showDescription: true, actions: true })}
        </div>
      </div>
      </div>
  </section>`;
}

function selectedStatusGroup(groups, params = new URLSearchParams()) {
  const requestedCategory = sanitizeIdentifier(params.get("statusCategory") || "");
  return groups.find((group) => group.meta.id === requestedCategory)
    || groups.find((group) => statusCategoryCounts(group.rows).open > 0)
    || groups[0]
    || { meta: statusCategoryMeta("operational-evidence"), rows: [] };
}

function renderOpsProjects(context, params = new URLSearchParams()) {
  const resourcesByProject = projectResourceRowsByProject(context);
  const selectedSlug = sanitizeIdentifier(params.get("project") || "");
  const selectedProject = context.projects.find((project) => project.slug === selectedSlug || project.id === selectedSlug);
  if (selectedProject) return renderOpsProjectDetailScreen(selectedProject, context, resourcesByProject.get(selectedProject.slug), params);

  const rows = sortedOpsProjects(context.projects)
    .map((project) => renderOpsProjectRow(project))
    .join("");
  return `<section class="ops-section ops-projects-redesign">
    <div class="ops-project-list" aria-label="Applicazioni">
      ${rows || empty("Nessuna applicazione", "Monta o dichiara una applicazione per gestirla dal portal.")}
    </div>
  </section>`;
}

function renderOpsVault(context) {
  const itemRows = context.vaultItems.map((item) => renderOpsVaultItem(item)).join("");
  return `<section class="ops-section ops-projects-redesign ops-vault-section">
    <div class="ops-vault-grid">
      <form method="post" action="/actions/vault-command" class="ops-vault-panel ops-vault-form" autocomplete="off">
        <input type="hidden" name="action" value="create">
        <input type="hidden" name="confirm" value="STORE-VAULT-SECRET">
        <div class="ops-vault-panel-head">
          <span class="ops-project-row-icon static" aria-hidden="true">${controlIcon("shield")}</span>
          <div>
            <h2>Aggiungi secret</h2>
            <p>Valore cifrato. Visibile solo quando premi mostra.</p>
          </div>
        </div>
        <div class="ops-vault-fields">
          <input name="itemKey" placeholder="nome_secret" aria-label="Nome secret" autocomplete="off" required>
          <input name="label" placeholder="Etichetta" aria-label="Etichetta secret" autocomplete="off">
          ${renderProjectSelect("projectId", "Applicazione", `<option value="platform">Platform</option>${sortedOpsProjects(context.projects).map((project) => `<option value="${escapeHtml(project.slug)}">${escapeHtml(project.name)}</option>`).join("")}`)}
          ${renderProjectSelect("targetEnv", "Ambiente", '<option value="local">Local</option><option value="staging">Staging</option><option value="production">Production</option>')}
          ${renderProjectSelect("kind", "Tipo secret", '<option value="application">Applicazione</option><option value="database">Database</option><option value="provider">Provider</option><option value="storage">Storage</option><option value="docker">Docker</option><option value="kms">KMS</option>')}
          <input name="username" placeholder="Utente / account" aria-label="Utente o account" autocomplete="off">
          <input name="url" placeholder="URL / host" aria-label="URL o host" autocomplete="off">
          <input type="number" min="0" max="3650" name="rotationDays" value="90" aria-label="Giorni rotazione">
          <input type="password" name="value" placeholder="Valore secret" aria-label="Valore secret" autocomplete="new-password" required>
        </div>
        <button class="ops-button primary" type="submit">${controlIcon("save")} Salva secret</button>
      </form>
      <div class="ops-vault-panel ops-vault-inventory">
        <div class="ops-vault-list-head">
          <div>
            <h2>Secret salvati</h2>
            <p>${escapeHtml(context.existingVaultImport?.importableCount ? `${context.existingVaultImport.importableCount} secret esistenti importabili` : "Secret esistenti gia indicizzati o non presenti.")}</p>
          </div>
          <form method="post" action="/actions/vault-command" class="ops-vault-import-form">
            <input type="hidden" name="action" value="import-existing">
            <input type="hidden" name="confirm" value="IMPORT-EXISTING-SECRETS">
            <button class="ops-button secondary compact" type="submit">${controlIcon("refresh")} Importa esistenti</button>
          </form>
          <span class="ops-state ${context.vaultItems.length ? "good" : "warn"}">${escapeHtml(String(context.vaultItems.length))}</span>
        </div>
        <div class="ops-vault-list" aria-label="Secret salvati nel vault">
          ${itemRows || empty("Vault vuoto", "Aggiungi il primo secret cifrato.")}
        </div>
      </div>
    </div>
  </section>`;
}

function renderOpsVaultItem(item) {
  const deleteConfirm = `DELETE-VAULT-SECRET:${item.id}`;
  const revealConfirm = `REVEAL-VAULT-SECRET:${item.id}`;
  const project = item.projectId === "platform" ? "Platform" : item.projectId;
  const rotation = item.rotationDays ? `rotazione ${item.rotationDays} giorni` : "rotazione non impostata";
  return `<article class="ops-vault-item" id="vault-${escapeHtml(item.id)}">
    <span class="ops-project-row-icon static" aria-hidden="true">${controlIcon("shield")}</span>
    <span class="ops-vault-item-main">
      <strong>${escapeHtml(item.label || item.itemKey)}</strong>
      <small>${escapeHtml(`${item.itemKey} / ${project} / ${item.environment} / ${item.kind}`)}</small>
      <small>${escapeHtml(`${item.username || "utente non impostato"} / ${item.url || "host non impostato"} / ${rotation}`)}</small>
      <small>Valore protetto. Premi mostra per leggerlo.</small>
      <span class="ops-vault-reveal" data-vault-reveal-box>
        <input type="password" value="" placeholder="Protetto" readonly aria-label="Valore ${escapeHtml(item.label || item.itemKey)}" data-vault-reveal-value>
        <button class="ops-button secondary compact" type="button" data-vault-reveal-action data-vault-id="${escapeHtml(item.id)}" data-vault-confirm="${escapeHtml(revealConfirm)}">${controlIcon("eye")} Mostra</button>
        <button class="ops-button secondary compact" type="button" data-vault-copy-action disabled>${controlIcon("copy")} Copia</button>
      </span>
    </span>
    <form method="post" action="/actions/vault-command" class="ops-vault-delete-form">
      <input type="hidden" name="action" value="delete">
      <input type="hidden" name="id" value="${escapeHtml(item.id)}">
      <input type="hidden" name="confirm" value="${escapeHtml(deleteConfirm)}">
      <button class="ops-button danger compact" type="submit">${controlIcon("trash")} Elimina</button>
    </form>
  </article>`;
}

function sortedOpsProjects(projects) {
  return [...(projects || [])].sort((a, b) => projectRuntimeSort(a.runtime) - projectRuntimeSort(b.runtime) || a.name.localeCompare(b.name));
}

function renderOpsProjectRow(project) {
  const state = projectOpsState(project);
  const detailHref = `/?section=projects&project=${encodeURIComponent(project.slug)}`;
  return `<div class="ops-project-row" id="project-${escapeHtml(project.slug)}" role="link" tabindex="0" data-project-row-link="${escapeHtml(detailHref)}" aria-label="Apri dettagli ${escapeHtml(project.name)}">
    <span class="ops-project-row-icon ${escapeHtml(project.runtime)}" aria-hidden="true">${controlIcon(projectRuntimeIcon(project.runtime))}</span>
    <span class="ops-project-row-name">
      <span class="ops-project-state-dot ${escapeHtml(projectStatusTone(project, state))}" aria-hidden="true"></span>
      <strong>${escapeHtml(project.name)}</strong>
    </span>
    <span class="ops-project-row-host">
      <small>Host</small>
      <a class="ops-project-host-link ops-fit-link" href="${escapeHtml(project.href)}" target="_blank" rel="noopener noreferrer" data-fit-single-line aria-label="Apri ${escapeHtml(project.name)} in una nuova scheda">${escapeHtml(project.host)}</a>
    </span>
    <span class="ops-project-row-runtime">
      <small>Runtime</small>
      <strong>${escapeHtml(projectRuntimeDisplay(project.runtime))}</strong>
    </span>
    <span class="ops-project-row-arrow" aria-hidden="true">${controlIcon("chevron")}</span>
  </div>`;
}

function renderOpsProjectDetailScreen(project, context, resourceSummary, params = new URLSearchParams()) {
  const databases = projectDatabases(context, project);
  const summary = resourceSummary || projectResourceSummary(context, project);
  const state = projectOpsState(project);
  const fileManager = renderProjectDetailFileManager(context, project, params);
  const databaseList = renderProjectDetailDatabaseList(context, project, databases);
  const resourcePanel = renderProjectDetailResources(summary, project);
  const backupPanel = renderProjectDetailBackups(context, project);
  return `<section class="ops-section ops-projects-redesign ops-project-detail-screen" id="project-${escapeHtml(project.slug)}">
    <div class="ops-project-detail-hero">
      <span class="ops-project-row-icon ${escapeHtml(project.runtime)}" aria-hidden="true">${controlIcon(projectRuntimeIcon(project.runtime))}</span>
      <span class="ops-project-row-name">
        <span class="ops-project-state-dot ${escapeHtml(projectStatusTone(project, state))}" aria-hidden="true"></span>
        <strong>${escapeHtml(project.name)}</strong>
      </span>
      <span class="ops-project-row-host">
        <small>Host</small>
        <a class="ops-project-host-link ops-fit-link" href="${escapeHtml(project.href)}" target="_blank" rel="noopener noreferrer" data-fit-single-line aria-label="Apri ${escapeHtml(project.name)} in una nuova scheda">${escapeHtml(project.host)}</a>
      </span>
      <span class="ops-project-row-runtime">
        <small>Runtime</small>
        <strong>${escapeHtml(projectRuntimeDisplay(project.runtime))}</strong>
      </span>
    </div>

    <div class="ops-project-detail-focus">
      ${fileManager}
      ${backupPanel}
      ${databaseList}
      ${resourcePanel}
    </div>
  </section>`;
}

function renderProjectDetailDatabaseList(context, project, databases) {
  const databaseItems = databases.map((database) => renderProjectDetailDatabaseRow(context, project, database)).join("");
  return `<div class="ops-project-detail-panel" id="project-databases">
    <div class="ops-project-detail-panel-head">
      <h3>Database</h3>
      <span class="ops-state ${databases.length ? "good" : "warn"}">${escapeHtml(databases.length ? `${databases.length} collegati` : "Nessuno")}</span>
    </div>
    <div class="ops-project-database-list">${databaseItems || empty("Nessun database", "Crea metadata database per questa applicazione.")}</div>
    ${renderProjectDetailDatabaseCreateForm(project)}
  </div>`;
}

function renderProjectDetailDatabaseRow(context, project, database) {
  const adminAction = databaseAdminAction(database);
  const updateConfirm = `UPDATE-DATABASE:${database.id}`;
  const credentialConfirm = `ROTATE-DATABASE-CREDENTIAL:${database.id}`;
  const deleteConfirm = databaseDeleteConfirmation(database, "REQUEST");
  const deleteOperation = context.databaseDeleteOperations.find((operation) => operation.database.id === database.id) || null;
  const credentialLabel = databaseCredentialDisplayLabel(database, project);
  return `<div class="ops-project-database-row" id="database-${escapeHtml(database.id)}">
    <div class="ops-project-database-main">
      <span class="ops-project-detail-item-icon">${controlIcon("databases")}</span>
      <span>
        <strong>${escapeHtml(databaseDisplayName(database))}</strong>
        <small>${escapeHtml(`Nome DB: ${database.name} / ${database.engine} / utente: ${database.ownerRole}`)}</small>
        <small>${escapeHtml(credentialLabel)}. Valore non mostrato.</small>
      </span>
      <a class="ops-icon-button" href="${escapeHtml(adminAction.href)}" target="_blank" rel="noopener noreferrer" aria-label="${escapeHtml(adminAction.ariaLabel)}">${controlIcon("external")}</a>
    </div>
    <form class="ops-project-database-edit-form" method="post" action="/actions/database-command">
      <input type="hidden" name="action" value="update">
      <input type="hidden" name="id" value="${escapeHtml(database.id)}">
      <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
      <input type="hidden" name="returnTo" value="project-detail">
      <input type="hidden" name="confirm" value="${escapeHtml(updateConfirm)}">
      <input name="displayName" value="${escapeHtml(databaseDisplayName(database))}" aria-label="Nome visualizzato database">
      <button class="ops-button secondary compact" type="submit">${controlIcon("save")} Salva</button>
    </form>
    <form class="ops-project-database-edit-form" method="post" action="/actions/database-command">
      <input type="hidden" name="action" value="credential">
      <input type="hidden" name="id" value="${escapeHtml(database.id)}">
      <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
      <input type="hidden" name="returnTo" value="project-detail">
      <input type="hidden" name="confirm" value="${escapeHtml(credentialConfirm)}">
      <input type="password" name="password" value="" placeholder="Nuova password" aria-label="Nuova password database" autocomplete="new-password">
      <button class="ops-button secondary compact" type="submit">${controlIcon("refresh")} Password</button>
    </form>
    <div class="ops-project-database-actions">
      ${deleteOperation ? renderDatabaseDeleteOperationControls(database, project, deleteOperation) : `<form method="post" action="/actions/database-command">
        <input type="hidden" name="action" value="delete">
        <input type="hidden" name="id" value="${escapeHtml(database.id)}">
        <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="returnTo" value="project-detail">
        <input type="hidden" name="confirm" value="${escapeHtml(deleteConfirm)}">
        <input type="hidden" name="idempotencyKey" value="${escapeHtml(rid())}">
        <input name="typedName" value="" placeholder="Digita ${escapeHtml(database.name)}" aria-label="Nome database da eliminare" autocomplete="off" required>
        <button class="ops-button danger compact" type="submit">${controlIcon("trash")} Richiedi eliminazione</button>
      </form>`}
    </div>
  </div>`;
}

function renderDatabaseDeleteOperationControls(database, project, operation) {
  const statusLabel = {
    "evidence-verified": "Evidence verificata",
    approved: "Approvata",
    executing: "In esecuzione",
    "database-dropped": "Database eliminato, cleanup in corso",
    failed: "Fallita prima del drop",
    "rollback-required": "Rollback richiesto",
  }[operation.status] || operation.status;
  if (new Set(["executing", "database-dropped", "rollback-required"]).has(operation.status)) {
    return `<div class="ops-project-database-delete-state"><strong>${escapeHtml(statusLabel)}</strong><small>Operazione ${escapeHtml(operation.id)}. Nessun retry automatico dopo il drop.</small></div>`;
  }
  const approve = new Set(["evidence-verified", "failed"]).has(operation.status);
  const action = approve ? "delete-approve" : "delete-execute";
  const phase = approve ? "APPROVE" : "EXECUTE";
  const label = approve ? "Approva eliminazione" : "Esegui eliminazione";
  return `<form method="post" action="/actions/database-command">
    <input type="hidden" name="action" value="${escapeHtml(action)}">
    <input type="hidden" name="operationId" value="${escapeHtml(operation.id)}">
    <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
    <input type="hidden" name="returnTo" value="project-detail">
    <input type="hidden" name="confirm" value="${escapeHtml(databaseDeleteConfirmation(database, phase, operation.id))}">
    <input name="typedName" value="" placeholder="Digita ${escapeHtml(database.name)}" aria-label="Conferma nome database" autocomplete="off" required>
    <span class="ops-state warn">${escapeHtml(statusLabel)}</span>
    <button class="ops-button danger compact" type="submit">${controlIcon(approve ? "shield" : "trash")} ${escapeHtml(label)}</button>
  </form>`;
}

function renderProjectDetailDatabaseCreateForm(project) {
  return `<form class="ops-project-database-create-form" method="post" action="/actions/database-command">
    <input type="hidden" name="action" value="create">
    <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
    <input type="hidden" name="returnTo" value="project-detail">
    <input type="hidden" name="confirm" value="CREATE-DATABASE">
    ${renderProjectSelect("engine", "Motore database", '<option value="mariadb">MariaDB</option><option value="postgres">PostgreSQL</option>')}
    <input name="name" placeholder="${escapeHtml(`${project.slug.replace(/-/g, "_")}_app`)}" aria-label="Nome nuovo database">
    <input type="password" name="password" value="" placeholder="Password" aria-label="Password nuovo database" autocomplete="new-password" required>
    <button class="ops-button secondary compact" type="submit">${controlIcon("plus")} Crea DB</button>
  </form>`;
}

function renderProjectSelect(name, label, options, attributes = "") {
  return `<label class="ops-project-select">
    <select name="${escapeHtml(name)}" aria-label="${escapeHtml(label)}"${attributes}>
      ${options}
    </select>
    <span class="ops-project-select-chevron" aria-hidden="true">${controlIcon("chevron-down")}</span>
  </label>`;
}

function databaseCredentialStatusLabel(status) {
  const labels = {
    protected: "protetta",
    "secret-ref-set": "secret collegato",
    "secret-file-set": "modificabile, non visibile",
    "rotation-requested": "rotazione richiesta",
    "rotation-requested-secret-ref": "rotazione richiesta con secret",
    missing: "mancante",
  };
  return labels[status] || "protetta";
}

function databaseCredentialDisplayLabel(database, project) {
  if (database.credentialRef) return `Secret: ${database.credentialRef}`;
  if (database.credentialFile || database.adminPasswordFile || database.passwordFile) return "Password: modificabile, non visibile";
  if (!databaseAllowsGenericProjectCredential(database, project)) return "Password: da configurare";
  return `Password: ${databaseCredentialStatusLabel(database.credentialStatus)}`;
}

function renderProjectDetailResources(summary) {
  const resourceRows = [
    ["CPU", summary.cpu],
    ["RAM", summary.memory],
    ["Disco", summary.disk],
    ["Container", summary.containers],
  ].map(([label, value]) => `<div class="ops-project-detail-fact"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
  return `<div class="ops-project-detail-panel" id="project-resources">
    <div class="ops-project-detail-panel-head ops-project-resource-head">
      <h3>Risorse utilizzate</h3>
    </div>
    <div class="ops-project-detail-resource-grid">${resourceRows}</div>
  </div>`;
}

function renderProjectDetailBackups(context, project) {
  const inventory = applicationBackupInventory(context, project);
  const restoreOptions = inventory.restoreOptions || [];
  const backupRows = restoreOptions.slice(0, 18).map(renderProjectDetailBackupRow).join("");
  const optionRows = restoreOptions.map((option) => `<option value="${escapeHtml(option.path)}">${escapeHtml(option.label)}</option>`).join("");
  const restoreDisabled = restoreOptions.length ? "" : " disabled";
  return `<div class="ops-project-detail-panel" id="project-backups">
    <div class="ops-project-detail-panel-head">
      <h3>Backup</h3>
      <form method="post" action="/actions/backup-command" class="ops-project-backup-head-form">
        <input type="hidden" name="action" value="backup">
        <input type="hidden" name="scope" value="application">
        <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="returnTo" value="project-detail">
        <input type="hidden" name="backupMode" value="all">
        <button class="ops-button secondary" type="submit">${controlIcon("backups")} Avvia backup</button>
      </form>
    </div>
    <div class="ops-project-backup-list" aria-label="Backup disponibili per ${escapeHtml(project.name)}">
      ${backupRows || empty("Nessun backup", "Avvia il primo backup dell'applicazione.")}
    </div>
    <div class="ops-project-backup-actions">
      <form method="post" action="/actions/backup-command" class="ops-project-backup-restore-form">
        <input type="hidden" name="action" value="restore">
        <input type="hidden" name="scope" value="application">
        <input type="hidden" name="projectId" value="${escapeHtml(project.slug)}">
        <input type="hidden" name="returnTo" value="project-detail">
        ${renderProjectSelect("backupRef", "Backup da ripristinare", optionRows || '<option value="">Nessun backup disponibile</option>', restoreDisabled)}
        ${renderProjectSelect("restoreMode", "Contenuto restore", '<option value="all">Tutto</option><option value="database">Solo database</option><option value="source">Solo sorgenti</option>', restoreDisabled)}
        <button class="ops-button danger" type="submit"${restoreDisabled}>${controlIcon("refresh")} Avvia restore drill</button>
      </form>
    </div>
  </div>`;
}

function renderProjectDetailBackupRow(option) {
  return `<div class="ops-project-backup-row" data-backup-ref="${escapeHtml(option.path)}">
    <span class="ops-project-detail-item-icon" aria-hidden="true">${controlIcon("backups")}</span>
    <span>
      <strong>${escapeHtml(option.name)}</strong>
      <small>${escapeHtml(`${option.kind} / ${option.modifiedAt || "data non disponibile"} / ${option.sizeLabel || "-"}`)}</small>
    </span>
  </div>`;
}

function renderProjectFileBreadcrumb(snapshot, projectHref) {
  const segments = String(snapshot.path || "").split("/").filter(Boolean);
  const crumbs = [`<a href="${projectHref("")}">Root</a>`];
  let current = "";
  for (const segment of segments) {
    current = joinRelativePath(current, segment);
    crumbs.push(`<a href="${projectHref(current)}">${escapeHtml(segment)}</a>`);
  }
  return `<nav class="ops-file-breadcrumb" aria-label="Percorso file">${crumbs.join('<span aria-hidden="true">/</span>')}</nav>`;
}

function renderProjectFileExplorerEntry(entry, projectHref) {
  const href = entry.browsable ? projectHref(entry.path) : "";
  const type = entry.type || "file";
  const icon = type === "directory" ? "folder" : type === "symlink" ? "external" : "file";
  const tag = entry.browsable ? "a" : "button";
  const tagAttributes = entry.browsable ? `href="${href}"` : 'type="button"';
  return `<${tag} class="ops-file-tile ${escapeHtml(type)}" ${tagAttributes}
    role="option"
    aria-selected="false"
    data-file-entry
    data-file-name="${escapeHtml(entry.name)}"
    data-file-path="${escapeHtml(entry.path || entry.name)}"
    data-file-type="${escapeHtml(type)}"
    data-file-size="${escapeHtml(entry.sizeLabel || "-")}"
    data-file-modified="${escapeHtml(entry.modifiedAt || "-")}"
    data-file-open-url="${escapeHtml(href)}">
    <span class="ops-file-tile-icon" aria-hidden="true">${controlIcon(icon)}</span>
    <span class="ops-file-tile-main">
      <strong>${escapeHtml(entry.name)}</strong>
      <small>${escapeHtml(entry.path || entry.name)}</small>
    </span>
    <span class="ops-file-tile-meta">
      <small>${escapeHtml(type)}</small>
      <small>${escapeHtml(entry.sizeLabel || "-")}</small>
      <small>${escapeHtml(entry.modifiedAt || "-")}</small>
    </span>
  </${tag}>`;
}

function renderProjectDetailFileManager(context, project, params) {
  let snapshot;
  try {
    snapshot = readProjectFiles(project.slug, params.get("path") || "", context);
  } catch (error) {
    snapshot = { available: false, path: "", parentPath: "", entries: [], message: error instanceof ValidationError ? error.message : "File applicazione non disponibili." };
  }
  const projectHref = (pathValue = "") => `/?section=projects&project=${escapeHtml(project.slug)}${pathValue ? `&path=${encodeURIComponent(pathValue)}` : ""}`;
  const entries = (snapshot.entries || []).map((entry) => renderProjectFileExplorerEntry(entry, projectHref)).join("");
  const parentHref = snapshot.parentPath || snapshot.path ? projectHref(snapshot.parentPath || "") : "";
  const entryCount = `${(snapshot.entries || []).length} elementi`;
  const refreshHref = projectHref(snapshot.path || "");
  return `<div class="ops-project-detail-panel ops-file-explorer" id="project-file-manager" data-file-manager data-file-manager-refresh-url="${escapeHtml(refreshHref)}" data-file-total-count="${escapeHtml(String((snapshot.entries || []).length))}">
    <div class="ops-file-explorer-head">
      <div>
        <h3>File manager</h3>
      </div>
      <div class="ops-file-commandbar" aria-label="Azioni file manager">
        ${snapshot.available ? `<label class="ops-file-search">
          ${controlIcon("search")}
          <input type="search" data-file-search placeholder="Cerca" aria-label="Cerca nella cartella corrente">
        </label>` : ""}
        ${parentHref ? `<a class="ops-icon-button" href="${parentHref}" aria-label="Vai alla cartella superiore" title="Su">${controlIcon("arrow-left")}</a>` : ""}
        <button class="ops-icon-button" type="button" data-file-refresh-action aria-label="Aggiorna file manager" title="Aggiorna">${controlIcon("refresh")}</button>
      </div>
    </div>
    ${renderProjectFileBreadcrumb(snapshot, projectHref)}
    ${snapshot.available ? `<div class="ops-file-workspace">
      <div class="ops-file-grid" role="listbox" aria-label="File di ${escapeHtml(project.name)}">
        ${entries || `<div class="ops-file-empty">${empty("Cartella vuota", "Nessun elemento navigabile trovato in questo path.")}</div>`}
        <div class="ops-file-search-empty" data-file-search-empty hidden>${empty("Nessun risultato", "La ricerca vale solo per la cartella aperta.")}</div>
      </div>
    </div>
    <div class="ops-file-statusbar">
      <span data-file-count>${escapeHtml(entryCount)}</span>
      <span>Secret, dipendenze e build output sono esclusi.</span>
    </div>
    <div class="ops-file-context-menu" data-file-context-menu hidden>
      <button type="button" data-file-menu-action="open">${controlIcon("folder")} Apri</button>
      <button type="button" data-file-menu-action="copy-path">${controlIcon("copy")} Copia percorso</button>
      <button type="button" data-file-menu-action="copy-name">${controlIcon("copy")} Copia nome</button>
    </div>` : empty("File non disponibili", snapshot.message || "I sorgenti applicazione non sono montati.")}
  </div>`;
}

function projectRuntimeDisplay(runtime) {
  if (runtime === "php") return "PHP Apache";
  if (runtime === "node") return "Node/Next";
  if (runtime === "static") return "Static";
  return humanName(runtime || "runtime");
}

function projectRuntimeIcon(runtime) {
  if (runtime === "php") return "file";
  if (runtime === "node") return "cube";
  if (runtime === "static") return "globe";
  return "projects";
}

function projectRuntimeSort(runtime) {
  if (runtime === "php") return 1;
  if (runtime === "node") return 2;
  if (runtime === "static") return 3;
  return 9;
}

function projectOpsState(project) {
  if (project.archivedAt || project.status === "archived") return { status: "archived", label: "Archiviata", detail: "Fuori dal routing" };
  if (project.filesystemExists === false) return { status: "offline", label: "File mancanti", detail: "Sorgenti non montati" };
  if (project.enabled) return { status: "online", label: "Online", detail: "Raggiungibile dal router" };
  return { status: "offline", label: "Fermata", detail: "Routing disabilitato" };
}

function projectStatusTone(project, state = projectOpsState(project)) {
  if (state.status === "online") return "good";
  if (project.filesystemExists === false) return "bad";
  return "warn";
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
  return {
    cpu: measuredContainers.length ? measuredCpuLabel(measuredContainers, hostCores) : usage.cpuMessage || "Metriche container non disponibili",
    memory: memoryBytes != null ? usageBytesLabel(memoryBytes) : usage.memoryMessage || "Metriche container non disponibili",
    disk: usage.diskAvailable ? `${usageBytesLabel(usage.diskBytes)} (${Number(usage.files || 0)} file)` : "Non disponibile",
    containers: containers.length ? containers.map((item) => `${item.container}:${item.runtimeStatus || "unknown"}`).join(", ") : `${dedicatedRuntimeName(project)} atteso`,
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
    const adminAction = databaseAdminAction(database);
    return `<div class="ops-row-actions">
    <a class="ops-icon-button" href="${escapeHtml(adminAction.href)}" target="_blank" rel="noopener noreferrer" aria-label="${escapeHtml(adminAction.ariaLabel)}">${controlIcon("external")}</a>
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

function databaseAdminAction(database) {
  const admin = databaseAdminTool(database);
  const confirmation = `${admin.confirmPrefix}:${database.id}`;
  const href = `${admin.loginPath}?databaseId=${encodeURIComponent(database.id)}&confirm=${encodeURIComponent(confirmation)}`;
  return {
    ...admin,
    href,
    ariaLabel: `Apri ${databaseDisplayName(database)} in ${admin.label} con accesso limitato`,
  };
}

function databaseAdminTool(database) {
  if (database.engine === "postgres") {
    return {
      label: "phpPgAdmin",
      confirmPrefix: "OPEN-PHPPGADMIN",
      loginPath: "/actions/phppgadmin-login",
    };
  }
  return {
    label: "phpMyAdmin",
    confirmPrefix: "OPEN-PHPMYADMIN",
    loginPath: "/actions/phpmyadmin-login",
  };
}

function resolveMariaDbCredential(database, project) {
  const metadataUser = sanitizeDatabasePrincipal(database.adminUser || database.ownerRole || "");
  const metadataPassword = readCredentialPasswordFile(database.credentialFile || database.adminPasswordFile || database.passwordFile || "", project);
  if (metadataUser && metadataPassword) return { user: metadataUser, password: metadataPassword, source: "database-metadata" };
  const requireDatabaseName = !databaseAllowsGenericProjectCredential(database, project);
  const projectCredential = readProjectMariaDbCredential(database, project, { requireDatabaseName });
  if (projectCredential) return projectCredential;
  const phpCredential = readProjectPhpMariaDbCredential(database, project, { requireDatabaseName });
  if (phpCredential) return phpCredential;
  return null;
}

function resolvePostgresCredential(database, project) {
  const metadataUser = sanitizeDatabasePrincipal(database.adminUser || database.ownerRole || "");
  const metadataPassword = readCredentialPasswordFile(database.credentialFile || database.adminPasswordFile || database.passwordFile || "", project);
  if (metadataUser && metadataPassword) return { user: metadataUser, password: metadataPassword, source: "database-metadata" };
  return null;
}

function databaseAllowsGenericProjectCredential(database, project) {
  if (!database || !project) return false;
  const databaseName = normalizeDatabaseCredentialName(database.name);
  const projectTokens = [
    project.slug,
    project.id,
    ...(Array.isArray(project.aliases) ? project.aliases : []),
  ].map((value) => normalizeDatabaseCredentialName(value)).filter(Boolean);
  return projectTokens.includes(databaseName);
}

function normalizeDatabaseCredentialName(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

function readProjectMariaDbCredential(database, project, options = {}) {
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
    if (options.requireDatabaseName && !dbName) continue;
    if (dbName && dbName !== database.name) continue;
    const user = sanitizeDatabasePrincipal(firstEnvValue(env, ["PHPMYADMIN_USER", "PMA_USER", "DB_USERNAME", "DB_USER", "DATABASE_USER", "MYSQL_USER", "MARIADB_USER"]) || database.ownerRole || "");
    const password = firstEnvValue(env, ["PHPMYADMIN_PASSWORD", "PMA_PASSWORD", "DB_PASSWORD", "DB_PASS", "DATABASE_PASSWORD", "DATABASE_PASS", "MYSQL_PASSWORD", "MYSQL_PASS", "MARIADB_PASSWORD", "MARIADB_PASS"]);
    if (user && password) return { user, password, source: `project-env:${fileName}` };
  }
  return null;
}

function readProjectPhpMariaDbCredential(database, project, options = {}) {
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
    if (options.requireDatabaseName && !dbName) continue;
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

function renderOpsMetric(label, value, detail, tone = "info") {
  return `<div class="ops-metric ${escapeHtml(tone)}">
    <span>${escapeHtml(label)}</span>
    <strong>${escapeHtml(String(value))}</strong>
    <small>${escapeHtml(String(detail || ""))}</small>
  </div>`;
}

function statusRunStepDefinitions() {
  return [
    { id: "portal-through-waf", label: "Portal via WAF", category: "domain-edge" },
    { id: "waf-sensitive-file-block", label: "File sensibili bloccati", category: "security" },
    { id: "go-no-go-report-readable", label: "Report go/no-go", category: "go-live" },
    { id: "go-no-go-verdict", label: "Decisione produzione", category: "go-live" },
    { id: "readiness-matrix-readable", label: "Matrice readiness", category: "governance" },
  ];
}

function statusRunStepDefinitionsForRows(rows, category) {
  const cleanCategory = sanitizeIdentifier(category || "");
  const base = statusRunStepDefinitions().filter((step) => !cleanCategory || step.category === cleanCategory);
  const seen = new Set(base.map((step) => step.id));
  const rowSteps = rows
    .map((row) => ({
      id: sanitizeIdentifier(row.technicalId || row.id || ""),
      label: row.control || row.technicalId || "Controllo",
      category: row.category || cleanCategory || "operational-evidence",
    }))
    .filter((step) => step.id && !seen.has(step.id))
    .map((step) => {
      seen.add(step.id);
      return step;
    });
  return [...base, ...rowSteps];
}

function renderStatusRunSteps(run, steps = statusRunStepDefinitions()) {
  const checks = Array.isArray(run?.checks) ? run.checks : [];
  const byId = new Map(checks.map((check) => [check.id, check]));
  return `<div class="ops-status-run-steps" data-status-run-steps>
    ${steps.map((step, index) => {
      const check = byId.get(step.id);
      const state = statusRunStepState(check);
      const detail = check?.detail || (run ? "Non presente nell'ultimo run." : "In attesa di esecuzione.");
      return `<div class="ops-status-run-step ${escapeHtml(state.className)}" data-status-run-step="${escapeHtml(step.id)}" data-status-run-step-index="${escapeHtml(String(index))}" data-status-run-step-category="${escapeHtml(step.category)}">
        <span class="ops-status-run-step-mark" data-status-run-step-mark>${escapeHtml(state.mark)}</span>
        <div>
          <strong>${escapeHtml(step.label)}</strong>
          <span data-status-run-step-detail>${escapeHtml(detail)}</span>
        </div>
      </div>`;
    }).join("")}
  </div>`;
}

function statusRunStepState(check) {
  if (!check) return { mark: "-", className: "idle" };
  if (check.status === "passed" || check.status === "success") return { mark: "V", className: "passed" };
  return { mark: "X", className: "failed" };
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
      category: check.category,
      source: check.source || "Test reale",
      status: check.status,
      reason: check.detail || "",
      action: check.status === "passed" ? "Nessuna azione immediata." : check.nextAction,
      required: check.required,
      reportPath: check.reportPath || "",
    }));
  }
  for (const check of context.goNoGo?.checks || []) {
    const displayCheck = goNoGoDisplayCheck(check);
    const passed = displayCheck.status === "passed";
    push(statusTableRow({
      id: `go-no-go:${displayCheck.name}`,
      control: friendlyCheckName(displayCheck.name),
      technicalId: displayCheck.name,
      category: displayCheck.category,
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
      category: check.category,
      source: check.source || "Documentazione",
      status: check.status,
      reason: check.detail || "",
      action: check.status === "passed" ? "Nessuna azione immediata." : check.nextAction,
      required: check.required,
    }));
  }
  return dedupeStatusRows(rows);
}

function statusRowsForContext(context) {
  return Array.isArray(context.statusRows) ? context.statusRows : opsStatusRows(context);
}

function dedupeStatusRows(rows) {
  const groups = new Map();
  for (const row of rows) {
    const key = statusDedupeKey(row);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }
  return [...groups.entries()].map(([key, group]) => mergeStatusRows(key, group));
}

function statusDedupeKey(row) {
  const id = sanitizeIdentifier(row?.technicalId || row?.id || "");
  if (["go-no-go-verdict", "production-go-no-go", "production-readiness-live"].includes(id)) return "go-live-decision";
  if (id === "deploy-vps") return "vps-deploy-protected";
  if (id === "vps-go-live") return "vps-go-live-orchestration";
  if (["go-no-go-report-readable", "readiness-matrix-readable"].includes(id)) return id;
  if (id.includes("pre-go-live")) return "pre-go-live-evidence";
  if (id.includes("github-actions-config") || id.includes("automatic-ci-cd-deploy") || id.includes("remote-ci-cd")) return "github-actions-runtime";
  if (id.includes("github-branch-protection") || id.includes("github-environments")) return "github-governance";
  if (id.includes("real-dns") || id.includes("production-preflight") || id.includes("external-uptime") || id.includes("public-https") || id.includes("tls-https")) return "public-domain-dns-https-uptime";
  if (id.includes("cloudflare-access") || id.includes("admin-access-mfa-vpn") || id.includes("cloudflare-from-zero")) return "cloudflare-access-admin";
  if (id.includes("cloudflare-origin-lock") || id.includes("waf-rate") || id.includes("rate-limit") || id.includes("rate-limiting")) return "public-edge-waf-rate-limit";
  if (id.includes("dast-zap")) return "staging-dast";
  if (id.includes("hosted-workload-isolation")) return "hosted-workload-routing-boundary";
  if (id.includes("offsite") || id.includes("disaster-recovery") || id.includes("rpo") || id.includes("rto") || id === "dr-evidence" || id.includes("database-service-governance") || id.includes("restore-tested")) return "offsite-backup-restore-rpo-rto";
  if (id.includes("load-benchmark") || id.includes("load-performance") || id === "load-benchmark") return "public-load-benchmark";
  if (id.includes("ha-multi-node")) return "ha-multi-node-readiness";
  if (id.includes("staging") && !id.includes("dast-zap")) return "staging-separation";
  if (id.includes("operations-runbook")) return "operations-runbook-final-evidence";
  if (id.includes("sign-images") || id.includes("supply-chain-sbom-signing-provenance")) return "image-signing-provenance";
  if (id.includes("feature-flags")) return "feature-flags-kill-switches";
  if (id.includes("vulnerability-disclosure")) return "vulnerability-disclosure-process";
  if (id.includes("compliance-gdpr") || id.includes("soc2")) return "compliance-evidence";
  if (id.includes("data-classification")) return "data-classification";
  if (id.includes("pentest")) return "penetration-test-readiness";
  if (id.includes("install-mariadb-backup-cron") || id.includes("install-postgres-backup-cron") || id.includes("backup-scheduler")) return "backup-scheduler";
  return id || sanitizeIdentifier(row?.id || "status-check");
}

function statusDedupeMeta(key) {
  const titles = {
    "go-live-decision": ["Decisione go live", "go-live-decision"],
    "vps-deploy-protected": ["Deploy VPS protetto", "deploy-vps"],
    "vps-go-live-orchestration": ["Orchestrazione VPS go-live", "vps-go-live"],
    "pre-go-live-evidence": ["Pacchetto pre go-live", "pre-go-live-evidence"],
    "github-actions-runtime": ["GitHub Actions runtime", "github-actions-runtime"],
    "github-governance": ["GitHub governance", "github-governance"],
    "public-domain-dns-https-uptime": ["Dominio, DNS, HTTPS e uptime pubblico", "public-domain-dns-https-uptime"],
    "cloudflare-access-admin": ["Cloudflare Access admin", "cloudflare-access-admin"],
    "public-edge-waf-rate-limit": ["WAF, bot protection e rate limit pubblico", "public-edge-waf-rate-limit"],
    "staging-dast": ["DAST staging", "staging-dast"],
    "hosted-workload-routing-boundary": ["Routing workload ospitati", "hosted-workload-routing-boundary"],
    "offsite-backup-restore-rpo-rto": ["Backup/restore off-site e RPO/RTO", "offsite-backup-restore-rpo-rto"],
    "public-load-benchmark": ["Benchmark pubblico", "public-load-benchmark"],
    "ha-multi-node-readiness": ["HA e multi-node readiness", "ha-multi-node-readiness"],
    "staging-separation": ["Staging separato da produzione", "staging-separation"],
    "operations-runbook-final-evidence": ["Runbook operativo finale", "operations-runbook-final-evidence"],
    "image-signing-provenance": ["Firma immagini e provenance", "image-signing-provenance"],
    "feature-flags-kill-switches": ["Feature flag e kill switch", "feature-flags-kill-switches"],
    "vulnerability-disclosure-process": ["Vulnerability disclosure", "vulnerability-disclosure"],
    "compliance-evidence": ["Compliance GDPR/SOC2-like", "compliance-evidence"],
    "data-classification": ["Data classification", "data-classification"],
    "penetration-test-readiness": ["Penetration test readiness", "penetration-test-readiness"],
    "backup-scheduler": ["Scheduler backup", "backup-scheduler"],
  };
  const [control, technicalId] = titles[key] || [null, null];
  return { control, technicalId };
}

function mergeStatusRows(key, rows) {
  const sorted = [...rows].sort(compareStatusRowsForMerge);
  const primary = sorted[0];
  const meta = statusDedupeMeta(key);
  const mergedTechnicalId = meta.technicalId || primary.technicalId || key;
  const covered = uniqueStrings(rows.map((row) => row.technicalId).filter((id) => id && id !== mergedTechnicalId));
  const coveredText = covered.length
    ? ` Copre anche ${covered.length} controlli collegati: ${covered.join(", ")}.`
    : "";
  const canonicalPass = canonicalPassedStatusEvidence(key);
  if (canonicalPass) {
    return statusTableRow({
      id: `dedupe:${key}`,
      control: meta.control || primary.control,
      technicalId: mergedTechnicalId,
      category: statusCategoryForCanonicalKey(key, primary),
      source: compactStatusSources(rows),
      status: "passed",
      reason: `${canonicalPass.reason}${coveredText}`,
      action: "Nessuna azione immediata.",
      required: rows.some((row) => row.required !== false),
      reportPath: canonicalPass.reportPath || primary.reportPath || rows.find((row) => row.reportPath)?.reportPath || "",
    });
  }
  const mergedStatus = primary.status;
  const mergedControl = meta.control || primary.control;
  const mergedReason = canonicalStatusReason(key, primary, rows) || primary.reason || "n.d.";
  const mergedAction = canonicalStatusAction(key, primary, rows) || primary.action || "Nessuna azione indicata.";
  return statusTableRow({
    id: `dedupe:${key}`,
    control: mergedControl,
    technicalId: mergedTechnicalId,
    category: statusCategoryForCanonicalKey(key, primary),
    source: compactStatusSources(rows),
    status: mergedStatus,
    reason: `${mergedReason}${coveredText}`,
    action: mergedAction,
    required: rows.some((row) => row.required !== false),
    reportPath: primary.reportPath || rows.find((row) => row.reportPath)?.reportPath || "",
  });
}

function canonicalPassedStatusEvidence(key) {
  if (key === "offsite-backup-restore-rpo-rto") {
    const evidence = readPassedDocumentedStatusEvidence("dr-evidence");
    const offsite = evidence?.payload?.offsiteEvidence;
    if (
      evidence
      && Array.isArray(evidence.payload?.issues)
      && evidence.payload.issues.length === 0
      && offsite?.latestRestoreOffsite === true
      && offsite?.latestRestoreCoverage?.complete === true
    ) {
      return {
        reportPath: evidence.reportPath,
        reason: "Restore off-site Restic completo su repository remoto, copertura dati completa e RPO/RTO verificati da evidence DR fresca.",
      };
    }
  }
  if (key === "backup-scheduler") {
    const evidence = readPassedDocumentedStatusEvidence("backup-scheduler");
    if (evidence) {
      return {
        reportPath: evidence.reportPath,
        reason: "Scheduler backup Docker attivo e healthy: backup locali e upload off-site sono pianificati ogni 8 ore, retention a 42 snapshot e cap remoto a 2.5 TB.",
      };
    }
  }
  return null;
}

function compareStatusRowsForMerge(a, b) {
  const severity = statusMergeSeverity(b.status) - statusMergeSeverity(a.status);
  if (severity) return severity;
  const source = statusSourcePriority(a.source) - statusSourcePriority(b.source);
  if (source) return source;
  return String(a.technicalId || "").localeCompare(String(b.technicalId || ""));
}

function statusMergeSeverity(status) {
  switch (String(status || "")) {
    case "failed":
    case "no-go":
      return 90;
    case "authorization-required":
      return 80;
    case "pending-provider":
    case "pending-live-proof":
    case "needs-work":
      return 70;
    case "warning":
    case "plan-only":
      return 50;
    case "passed":
    case "success":
    case "go":
      return 10;
    default:
      return 40;
  }
}

function statusSourcePriority(source = "") {
  const text = String(source).toLowerCase();
  if (text.includes("go live")) return 1;
  if (text.includes("test reale")) return 2;
  if (text.includes("report")) return 3;
  if (text.includes("production readiness")) return 4;
  if (text.includes("enterprise")) return 5;
  return 9;
}

function compactStatusSources(rows) {
  const sources = uniqueStrings(rows.map((row) => row.source).filter(Boolean));
  if (sources.length <= 2) return sources.join(" / ");
  return `${sources.slice(0, 2).join(" / ")} + ${sources.length - 2} fonti`;
}

function canonicalStatusReason(key, primary, rows) {
  if (primary.status === "passed" || primary.status === "success") return primary.reason;
  if (key === "offsite-backup-restore-rpo-rto") return "Restore locale completo e backup locali risultano coperti; manca la prova off-site Restic su repository remoto con restore completo e copertura RPO/RTO.";
  if (key === "vps-deploy-orchestration") return "Deploy/go-live VPS e' una procedura protetta: puo' modificare servizi, usare backup o validare rollback, quindi richiede finestra operativa.";
  if (key === "github-actions-runtime") return "Branch protection, environments e workflow passano; resta incompleta la configurazione runtime GitHub Actions per staging/production.";
  if (key === "staging-dast") return "Manca un target staging HTTPS raggiungibile da GitHub Actions per eseguire la baseline DAST.";
  if (key === "public-domain-dns-https-uptime") return "Manca la prova su dominio pubblico reale: DNS, HTTPS e monitor esterno non sono ancora verificati fuori dalla LAN.";
  if (key === "cloudflare-access-admin") return "Cloudflare Access/admin non e' ancora verificato come provider live per produzione.";
  if (key === "public-edge-waf-rate-limit") return "WAF e rate limit passano localmente, ma manca la prova dal public edge Cloudflare/dominio reale.";
  if (key === "pre-go-live-evidence") return "Il pacchetto pre go-live e' quasi completo: mancano production preflight reale, restore off-site Restic e runtime provider GitHub Actions.";
  if (key === "public-load-benchmark") return "Manca un benchmark fresco sul dominio pubblico finale.";
  if (key === "hosted-workload-routing-boundary") return "Manca la prova di routing produzione per wildcard DNS, Traefik e project-router sul dominio reale.";
  if (key === "staging-separation") return "Manca una prova di staging separato da produzione con target pubblico e configurazione propria.";
  if (key === "ha-multi-node-readiness") return "Manca una decisione/prova HA: l'ambiente attuale resta single-node.";
  if (key === "operations-runbook-final-evidence") return "Il runbook esiste, ma deve puntare ai report finali veri di dominio, provider e restore off-site.";
  if (key === "backup-scheduler") return "Manca una prova di scheduler backup attivo e verificato; le righe cron documentate da sole non bastano come evidence produzione.";
  if (key === "penetration-test-readiness") return "Manca evidence di penetration test readiness per l'infrastruttura eseguita o approvata.";
  if (key === "feature-flags-kill-switches") return "Manca evidence operativa di feature flag/kill switch per disabilitare funzionalita rischiose senza deploy.";
  if (key === "vulnerability-disclosure-process") return "Manca evidence del processo di vulnerability disclosure pubblicabile per la piattaforma.";
  if (key === "compliance-evidence") return "Manca evidence non-secret di compliance GDPR/SOC2-like applicabile alla piattaforma.";
  if (key === "data-classification") return "Manca evidence di classificazione dati e trattamento dei dati gestiti dall'infrastruttura.";
  return primary.reason;
}

function canonicalStatusAction(key, primary, rows) {
  if (primary.status === "passed" || primary.status === "success") return primary.action;
  if (key === "offsite-backup-restore-rpo-rto") return "Configura RESTIC_REPOSITORY remoto e RESTIC_PASSWORD_FILE, esegui offsite-backup-restic e offsite-restore-drill-restic completo, poi rilancia dr-evidence e production-go-no-go.";
  if (key === "vps-deploy-orchestration") return "Esegui solo con backup recente, finestra di manutenzione e conferma esplicita; poi conserva il report VPS go-live live.";
  if (key === "github-actions-runtime") return "Imposta DAST_TARGET su staging e completa le variabili/secrets production richieste; poi rilancia github-actions-config --verifyRemote e pre-go-live-evidence.";
  if (key === "staging-dast") return "Configura DAST_TARGET con un URL HTTPS staging reale raggiungibile da GitHub Actions e rilancia il controllo.";
  if (key === "public-domain-dns-https-uptime") return "Collega il dominio pubblico finale, verifica DNS/HTTPS da esterno e rilancia production-preflight, external-uptime-check e pre-go-live-evidence.";
  if (key === "cloudflare-access-admin") return "Configura/verifica Cloudflare Access per il dominio reale e archivia il report non-secret.";
  if (key === "public-edge-waf-rate-limit") return "Esegui WAF smoke e rate-limit evidence contro il dominio pubblico dietro Cloudflare.";
  if (key === "pre-go-live-evidence") return "Rilancia pre-go-live-evidence con includeProductionPreflight, includeOffsiteRestoreDryRun e verifyGithubRemote dopo dominio, Restic remoto e GitHub runtime.";
  if (key === "public-load-benchmark") return "Esegui load-benchmark sul dominio pubblico reale e conserva il report fresco.";
  if (key === "hosted-workload-routing-boundary") return "Verifica wildcard DNS e routing project-router sul dominio pubblico senza accoppiare app e infrastruttura.";
  if (key === "staging-separation") return "Configura staging separato, imposta DAST_TARGET e verifica route/secrets/volumi separati.";
  if (key === "ha-multi-node-readiness") return "Aggiungi un target multi-node oppure approva e documenta esplicitamente il rischio single-node per questa fase.";
  if (key === "operations-runbook-final-evidence") return "Completa i riferimenti del runbook dopo production preflight, Cloudflare/uptime e off-site restore reali.";
  if (key === "backup-scheduler") return "Avvia/verifica il backup scheduler Docker o un crontab production equivalente, poi archivia un report non-secret.";
  if (key === "penetration-test-readiness") return "Esegui o pianifica formalmente il pentest infrastrutturale e conserva evidence non-secret del risultato o dell'approvazione.";
  if (key === "feature-flags-kill-switches") return "Definisci i kill switch operativi della piattaforma e conserva evidence di verifica.";
  if (key === "vulnerability-disclosure-process") return "Pubblica o approva il processo di disclosure e conserva evidence del canale scelto.";
  if (key === "compliance-evidence") return "Archivia la matrice compliance non-secret con scope, controlli e responsabilita.";
  if (key === "data-classification") return "Archivia la classificazione dei dati gestiti dalla piattaforma e le regole di trattamento.";
  return primary.action;
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value || "").trim()).filter(Boolean))];
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

function statusTableRow({ id, control, technicalId, category = "", source, status, reason, action, required = true, reportPath = "" }) {
  const categoryMeta = statusCategoryMeta(statusCategoryKey({ technicalId, category, source, reason, action }));
  return sanitizeEvent({
    id,
    control,
    technicalId,
    category: categoryMeta.id,
    categoryLabel: categoryMeta.label,
    categoryDescription: categoryMeta.description,
    source,
    status,
    statusLabel: operationalStatusLabel(status, technicalId, source, reason, action),
    reason,
    action,
    required,
    reportPath,
  });
}

function operationalStatusLabel(status, technicalId, source = "", reason = "", action = "") {
  const cleanStatus = String(status || "");
  if (cleanStatus === "passed") return "Superato";
  if (cleanStatus === "success") return "Riuscito";
  if (cleanStatus === "go") return "GO LIVE";
  if (cleanStatus === "no-go") return "NO GO LIVE";
  const id = sanitizeIdentifier(technicalId || "");
  const text = `${id} ${source || ""} ${reason || ""} ${action || ""}`.toLowerCase();
  if (cleanStatus === "authorization-required") return "Serve autorizzazione";
  if (id.includes("pre-go-live")) return "Manca pre go-live";
  if (id.includes("staging")) return "Manca staging";
  if (id === "github-actions-runtime") return "Manca GitHub runtime";
  if (id === "public-domain-dns-https-uptime") return "Manca dominio";
  if (id === "staging-dast") return "Manca DAST staging";
  if (id === "backup-scheduler") return "Manca scheduler backup";
  if (id === "penetration-test-readiness") return "Manca pentest";
  if (id === "feature-flags-kill-switches") return "Manca kill switch";
  if (id === "vulnerability-disclosure") return "Manca disclosure";
  if (id === "compliance-evidence") return "Manca compliance";
  if (id === "data-classification") return "Manca classificazione";
  if (id.includes("ha-multi-node") || id.includes("multi-node")) return "Manca HA";
  if (id.includes("offsite") || id.includes("rpo") || id.includes("rto") || id.includes("disaster-recovery") || text.includes("restic")) return "Manca backup off-site";
  if (id.includes("hosted-workload-isolation") || text.includes("wildcard dns") || text.includes("project-router")) return "Manca routing pubblico";
  if (/(^|-)load($|-)/.test(id) || id.includes("benchmark") || text.includes("benchmark pubblico")) return "Manca benchmark";
  if (id.includes("cloudflare")) return "Manca Cloudflare";
  if (id.includes("waf") || id.includes("rate-limit") || id.includes("rate-limiting") || text.includes("protezione bot")) return "Manca WAF/rate limit";
  if (id.includes("real-dns") || id.includes("external-uptime") || id.includes("public-https") || id.includes("tls-https") || text.includes("dominio reale") || text.includes("dns pubblico")) return "Manca dominio";
  if (id.includes("github-actions-config") || text.includes("github actions runtime")) return "Manca GitHub runtime";
  if (id.includes("github") || text.includes("github")) return "Manca GitHub evidence";
  if (id.includes("release") || text.includes("attestation") || text.includes("sigstore")) return "Manca release evidence";
  if (id.includes("operations-runbook") || text.includes("runbook")) return "Manca runbook finale";
  if (cleanStatus === "pending-live-proof") return "Manca prova live";
  if (cleanStatus === "pending-provider") return "Manca provider";
  return friendlyGoNoGoStatus(cleanStatus);
}

function statusCategoryForCanonicalKey(key, primary = {}) {
  const categories = {
    "go-live-decision": "go-live",
    "vps-deploy-protected": "runtime-vps",
    "vps-go-live-orchestration": "runtime-vps",
    "pre-go-live-evidence": "go-live",
    "github-actions-runtime": "github-release",
    "github-governance": "github-release",
    "public-domain-dns-https-uptime": "domain-edge",
    "cloudflare-access-admin": "domain-edge",
    "public-edge-waf-rate-limit": "domain-edge",
    "staging-dast": "staging-ha",
    "hosted-workload-routing-boundary": "domain-edge",
    "offsite-backup-restore-rpo-rto": "backup-dr",
    "public-load-benchmark": "performance",
    "ha-multi-node-readiness": "staging-ha",
    "staging-separation": "staging-ha",
    "operations-runbook-final-evidence": "governance",
    "image-signing-provenance": "github-release",
    "feature-flags-kill-switches": "governance",
    "vulnerability-disclosure-process": "governance",
    "compliance-evidence": "governance",
    "data-classification": "governance",
    "penetration-test-readiness": "security",
    "backup-scheduler": "backup-dr",
  };
  return categories[key] || primary.category || "";
}

function statusCategoryKey({ technicalId = "", category = "", source = "", reason = "", action = "" } = {}) {
  const id = sanitizeIdentifier(technicalId || "");
  const cleanCategory = sanitizeIdentifier(category || "");
  const text = `${id} ${cleanCategory} ${source || ""} ${reason || ""} ${action || ""}`.toLowerCase();
  if (cleanCategory === "routing" || cleanCategory === "network" || cleanCategory === "edge") return "domain-edge";
  if (cleanCategory === "provider") {
    if (text.includes("github") || text.includes("sigstore") || text.includes("attestation") || text.includes("release")) return "github-release";
    if (text.includes("restic") || text.includes("backup") || text.includes("restore") || text.includes("disaster")) return "backup-dr";
    return "domain-edge";
  }
  if (cleanCategory === "runtime-evidence") {
    if (text.includes("backup") || text.includes("restore") || text.includes("dr-") || text.includes("disaster") || text.includes("restic")) return "backup-dr";
    if (text.includes("release") || text.includes("pre-go-live") || text.includes("go-no-go")) return "go-live";
    if (text.includes("vps")) return "runtime-vps";
    if (text.includes("load")) return "performance";
    if (text.includes("alert") || text.includes("retention") || text.includes("evidence-bundle")) return "observability-evidence";
  }
  if (cleanCategory === "protected-runtime") {
    if (text.includes("backup") || text.includes("restore") || text.includes("prune") || text.includes("sign-existing-postgres")) return "backup-dr";
    if (text.includes("deploy") || text.includes("vps")) return "runtime-vps";
    return "resilience-tests";
  }
  if (cleanCategory === "secret-protected" || text.includes("secret-manager") || text.includes("secret rotation") || text.includes("secrets")) return "secrets";
  if (cleanCategory === "local-policy") {
    if (text.includes("waf") || text.includes("rate-limit") || text.includes("security") || text.includes("vulnerability") || text.includes("pentest")) return "security";
    if (text.includes("backup") || text.includes("dr-") || text.includes("disaster")) return "backup-dr";
    if (text.includes("ha-") || text.includes("multi-node") || text.includes("staging")) return "staging-ha";
    if (text.includes("performance") || text.includes("load")) return "performance";
    if (text.includes("sbom") || text.includes("supply-chain") || text.includes("github") || text.includes("release")) return "github-release";
    if (text.includes("retention") || text.includes("alert") || text.includes("audit") || text.includes("logs")) return "observability-evidence";
    if (text.includes("governance") || text.includes("enterprise") || text.includes("readiness") || text.includes("maintainability")) return "governance";
    return "local-quality";
  }
  if (id.includes("go-no-go") || id.includes("pre-go-live") || id.includes("production-readiness-live")) return "go-live";
  if (id.includes("github") || id.includes("release") || id.includes("artifact") || id.includes("sigstore") || id.includes("sign-images") || id.includes("supply-chain")) return "github-release";
  if (id.includes("cloudflare") || id.includes("dns") || id.includes("domain") || id.includes("https") || id.includes("uptime") || id.includes("waf") || id.includes("route") || id.includes("router")) return "domain-edge";
  if (id.includes("backup") || id.includes("restore") || id.includes("dr-") || id.includes("rpo") || id.includes("rto") || id.includes("restic")) return "backup-dr";
  if (id.includes("ha-") || id.includes("multi-node") || id.includes("staging") || id.includes("dast")) return "staging-ha";
  if (id.includes("secret")) return "secrets";
  if (id.includes("security") || id.includes("pentest") || id.includes("vulnerability") || id.includes("rate-limit")) return "security";
  if (id.includes("load") || id.includes("performance") || id.includes("benchmark")) return "performance";
  if (id.includes("vps") || id.includes("deploy") || id.includes("bootstrap") || id.includes("hardening")) return "runtime-vps";
  if (id.includes("audit") || id.includes("alert") || id.includes("retention") || id.includes("health") || id.includes("evidence-bundle")) return "observability-evidence";
  if (id.includes("governance") || id.includes("enterprise") || id.includes("compliance") || id.includes("data-classification") || id.includes("feature-flags") || id.includes("runbook")) return "governance";
  return "local-quality";
}

function statusCategoryMeta(key) {
  const cleanKey = sanitizeIdentifier(key || "local-quality") || "local-quality";
  const categories = {
    "go-live": ["Go live e decisione", "Decisione finale, pacchetto pre go-live e report che dichiarano se si puo' andare online.", 10],
    "domain-edge": ["Dominio, edge e routing", "DNS pubblico, HTTPS, Cloudflare, WAF, rate limit, uptime e routing project-router.", 20],
    "github-release": ["GitHub, CI/CD e release", "Branch protection, environments, workflow, artifact, firma immagini e provenance.", 30],
    "backup-dr": ["Backup e disaster recovery", "Backup locali/off-site, restore drill, RPO/RTO, scheduler e prove di ripristino.", 40],
    "staging-ha": ["Staging e alta disponibilita", "Separazione staging/produzione, DAST e readiness multi-node.", 50],
    "security": ["Sicurezza tecnica", "Security smoke, secret scan, WAF locale, rate limit locale, vulnerability e pentest.", 60],
    "secrets": ["Secrets e vault", "Secret manager, rotazione, validazione locale e materiale sensibile protetto.", 70],
    "governance": ["Governance e compliance", "Runbook, policy, readiness enterprise, classificazione dati e processi operativi.", 80],
    "observability-evidence": ["Osservabilita ed evidence", "Audit log, health, alerting, retention, bundle evidence e monitoraggio.", 90],
    "performance": ["Performance e carico", "Benchmark pubblico, smoke carico e profilo prestazioni.", 100],
    "runtime-vps": ["Runtime Ubuntu/VPS", "Bootstrap, hardening, preflight, postdeploy e deploy protetto del server Ubuntu.", 110],
    "resilience-tests": ["Test di resilienza", "Chaos, fault injection, failure test e rollback controllato.", 120],
    "local-quality": ["Qualita locale repo", "Portabilita Linux, hygiene, coverage, test locali e controlli statici.", 130],
    "operational-evidence": ["Evidence operativa", "Controlli operativi senza categoria specifica.", 900],
  };
  const [label, description, order] = categories[cleanKey] || categories["local-quality"];
  return { id: cleanKey, label, description, order };
}

function groupStatusRowsByCategory(rows) {
  const groups = new Map();
  for (const row of rows) {
    const meta = statusCategoryMeta(row.category || statusCategoryKey(row));
    if (!groups.has(meta.id)) groups.set(meta.id, { meta, rows: [] });
    groups.get(meta.id).rows.push(row);
  }
  return [...groups.values()]
    .sort((a, b) => a.meta.order - b.meta.order || a.meta.label.localeCompare(b.meta.label))
    .map((group) => ({
      ...group,
      rows: [...group.rows].sort(compareStatusRowsForCategory),
    }));
}

function compareStatusRowsForCategory(a, b) {
  const severity = statusMergeSeverity(b.status) - statusMergeSeverity(a.status);
  if (severity) return severity;
  return String(a.control || a.technicalId || "").localeCompare(String(b.control || b.technicalId || ""));
}

function statusCategoryCounts(rows) {
  const total = rows.length;
  const passed = rows.filter((row) => row.status === "passed" || row.status === "success" || row.status === "go").length;
  const fix = rows.filter((row) => ["failed", "needs-work", "plan-only"].includes(row.status)).length;
  const missing = rows.filter((row) => ["authorization-required", "pending-live-proof", "pending-provider", "no-go"].includes(row.status)).length;
  return { total, passed, fix, missing, open: Math.max(0, total - passed) };
}

function renderStatusCategoryTable(category, rows, options = {}) {
  if (!rows.length) return empty("Nessun controllo", "Questa sezione non contiene controlli.");
  const counts = statusCategoryCounts(rows);
  const body = rows.map((row) => renderStatusCheckRow(row, options)).join("");
  return `<section class="ops-status-category" data-status-category="${escapeHtml(category.id)}">
    <div class="ops-status-category-head">
      <div>
        <strong>${escapeHtml(category.label)}</strong>
        ${options.showDescription ? `<span>${escapeHtml(category.description)}</span>` : ""}
      </div>
      <div class="ops-status-category-counts" aria-label="Conteggi categoria">
        <span><strong>${escapeHtml(String(counts.total))}</strong> totali</span>
        <span class="good"><strong>${escapeHtml(String(counts.passed))}</strong> OK</span>
        <span class="bad"><strong>${escapeHtml(String(counts.open))}</strong> aperti</span>
      </div>
    </div>
    <div class="ops-status-check-list">${body}</div>
  </section>`;
}

function renderStatusCheckRow(row, options = {}) {
  const tone = statusClass(row.status);
  return `<details class="ops-status-check-row ${escapeHtml(tone)}">
    <summary class="ops-status-check-summary">
      <span class="ops-status-check-dot ${escapeHtml(tone)}" aria-hidden="true"></span>
      <span class="ops-status-check-title">
        <strong>${escapeHtml(row.control)}</strong>
        <span>${escapeHtml(row.reason || row.technicalId || "n.d.")}</span>
      </span>
      <span class="ops-state ${escapeHtml(tone)}">${escapeHtml(row.statusLabel || friendlyGoNoGoStatus(row.status))}</span>
      ${options.actions ? `<form class="ops-status-check-run" method="post" action="/actions/status-check" data-status-run-form data-status-run-inline>
        <input type="hidden" name="scope" value="check">
        <input type="hidden" name="category" value="${escapeHtml(row.category)}">
        <input type="hidden" name="checkId" value="${escapeHtml(row.technicalId)}">
        <button class="ops-icon-button" type="submit" data-status-run-button aria-label="Esegui ${escapeHtml(row.control)}">${controlIcon("play")}</button>
      </form>` : ""}
    </summary>
    <div class="ops-status-check-details">
      <div>
        <small>ID</small>
        <p>${escapeHtml(row.technicalId)}</p>
      </div>
      <div>
        <small>Cosa fare</small>
        <p>${escapeHtml(row.action || "Nessuna azione indicata.")}</p>
      </div>
      <div>
        <small>Fonte</small>
        <p>${escapeHtml(row.source)}</p>
      </div>
      ${row.reportPath ? `<div>
        <small>Report</small>
        <p>${escapeHtml(row.reportPath)}</p>
      </div>` : ""}
    </div>
  </details>`;
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
  if (text.includes("github-actions-config")) {
    return "Manca la configurazione runtime di GitHub Actions: workflow e token passano, ma variabili/secrets provider per staging/production non sono completi.";
  }
  if (text.includes("pre-go-live")) {
    return "Manca il pacchetto pre go-live completo: production preflight reale, verifica GitHub Actions runtime/provider e restore off-site non sono tutti chiusi.";
  }
  if (text.includes("external-uptime") || text.includes("domain") || text.includes("dns") || text.includes("tls") || text.includes("https")) {
    return "Manca una prova esterna che dominio, DNS e HTTPS siano raggiungibili come richiesto.";
  }
  if (text.includes("cloudflare")) return "Cloudflare non è ancora provato come configurato e funzionante per la produzione.";
  if (text.includes("release")) {
    return "Manca o non copre tutti gli artefatti richiesti l'evidence di release/rollback.";
  }
  if (text.includes("github")) {
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
  if (text.includes("github-actions-config")) {
    return "Requisito GitHub Actions runtime: imposta DAST_TARGET per staging e le variabili/secrets production per deploy, Cloudflare e uptime provider; poi rilancia github-actions-config --verifyRemote.";
  }
  if (text.includes("pre-go-live")) {
    return "Requisito pre go-live: completa production preflight con dominio reale, off-site restore Restic e GitHub Actions runtime config; poi rilancia pre-go-live-evidence con includeProductionPreflight, includeOffsiteRestoreDryRun e verifyGithubRemote.";
  }
  if (text.includes("external-uptime") || text.includes("domain") || text.includes("dns") || text.includes("tls") || text.includes("https")) {
    return `Requisito dominio: verifica DNS, HTTPS e monitor esterno sul dominio pubblico.${evidence}`;
  }
  if (text.includes("cloudflare")) {
    return `Requisito Cloudflare: verifica Access, DNS/WAF o proxy Cloudflare sull'ambiente reale.${evidence}`;
  }
  if (text.includes("release")) {
    return `Requisito GitHub/release: genera evidence di release e rollback prima del go live.${evidence}`;
  }
  if (text.includes("github")) {
    return `Requisito GitHub: fai passare la workflow di verifica richiesta e conserva l'evidence del run.${evidence}`;
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
  if (!existsSync(dockerStatsFile)) return { available: false, capturedAt: "", stale: false, containers: [] };
  try {
    const parsed = JSON.parse(readFileSync(dockerStatsFile, "utf8"));
    const capturedAtEpoch = Number(parsed.capturedAtEpoch || (Date.parse(parsed.capturedAt || "") / 1000));
    const timestampDeltaMs = Number.isFinite(capturedAtEpoch) ? Date.now() - (capturedAtEpoch * 1000) : Number.POSITIVE_INFINITY;
    const ageMs = Number.isFinite(timestampDeltaMs) ? Math.max(0, timestampDeltaMs) : Number.POSITIVE_INFINITY;
    const timestampValid = Number.isFinite(timestampDeltaMs)
      && timestampDeltaMs >= -5000
      && timestampDeltaMs <= dockerStatsMaxAgeMs;
    const collectorHealthy = parsed.schemaVersion === 2
      && parsed.collector?.healthy === true
      && Number(parsed.collector?.expectedRunning || 0) > 0
      && Number(parsed.collector?.observed || 0) === Number(parsed.collector?.expectedRunning || 0);
    if (!collectorHealthy || !timestampValid) {
      return {
        available: false,
        capturedAt: sanitizeMessage(parsed.capturedAt || ""),
        stale: timestampDeltaMs > dockerStatsMaxAgeMs,
        futureTimestamp: timestampDeltaMs < -5000,
        ageMs: Number.isFinite(ageMs) ? ageMs : null,
        containers: [],
      };
    }
    const rawContainers = Array.isArray(parsed.containers) ? parsed.containers : [];
    const containers = rawContainers.map(dockerStatsContainerRecord).filter(Boolean);
    return {
      available: containers.length > 0,
      capturedAt: sanitizeMessage(parsed.capturedAt || ""),
      capturedAtEpoch,
      stale: false,
      ageMs,
      containers,
    };
  } catch {
    return { available: false, capturedAt: "", stale: false, containers: [] };
  }
}

function dockerStatsContainerRecord(item) {
  if (!item || typeof item !== "object") return null;
  const name = sanitizeRef(item.name || item.container || item.Name || item.Container || "");
  if (!name || name === "unknown") return null;
  const cpuPercent = parseDockerPercent(item.cpuPercent ?? item.CPUPerc ?? item.cpu ?? "");
  const explicitCpuCores = Number(item.cpuCores);
  const explicitMemoryBytes = Number(item.memoryUsageBytes);
  const memoryBytes = Number.isFinite(explicitMemoryBytes) && explicitMemoryBytes >= 0
    ? explicitMemoryBytes
    : parseDockerMemoryUsage(item.memoryUsage ?? item.MemUsage ?? item.memory ?? "");
  const cpuLimitCores = nullableNonNegativeNumber(item.cpuLimitCores);
  const memoryLimitBytes = nullableNonNegativeNumber(item.memoryLimitBytes);
  const memoryReservationBytes = nullableNonNegativeNumber(item.memoryReservationBytes);
  const pidsLimit = nullableNonNegativeNumber(item.pidsLimit);
  return {
    name,
    service: sanitizeRef(item.service || ""),
    status: sanitizeIdentifier(item.status || "running"),
    source: "docker-stats",
    cpuCores: Number.isFinite(explicitCpuCores) && explicitCpuCores >= 0 ? explicitCpuCores : cpuPercent != null ? cpuPercent / 100 : null,
    cpuPercent,
    memoryBytes,
    cpuLimitCores,
    memoryLimitBytes,
    memoryReservationBytes,
    pidsLimit,
    cpuLimitConfigured: cpuLimitCores != null,
    memoryLimitConfigured: memoryLimitBytes != null,
  };
}

function nullableNonNegativeNumber(value) {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function parseDockerPercent(value) {
  if (value == null || value === "") return null;
  const number = Number(String(value).replace("%", "").trim());
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
    const haystacks = [container.name, container.service].map((value) => resourceToken(value)).filter(Boolean);
    return haystacks.some((haystack) => exact.some((needle) => haystack === needle)
      || fallback.some((needle) => haystack === needle || haystack.includes(needle)));
  });
}

async function collectLiveResourceUsage({ projects, applications, webspaces }) {
  const capturedAt = new Date().toISOString();
  const prometheus = await readPrometheusResourceSnapshot();
  const dockerStats = readDockerStatsSnapshot();
  const projectDisks = new Map(await Promise.all(projects.map(async (project) => [
    project.slug,
    await readProjectDiskUsage(project),
  ])));
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
        cpuPercent: container.cpuPercent ?? (Number.isFinite(Number(container.cpuCores)) ? Number(container.cpuCores) * 100 : null),
        memoryBytes: container.memoryBytes,
        cpuLimitCores: container.cpuLimitCores ?? null,
        memoryLimitBytes: container.memoryLimitBytes ?? null,
        memoryReservationBytes: container.memoryReservationBytes ?? null,
        pidsLimit: container.pidsLimit ?? null,
        runtimeStatus: container.status || "running",
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
        cpuLimitCores: container.cpuLimitCores,
        memoryLimitBytes: container.memoryLimitBytes,
        memoryReservationBytes: container.memoryReservationBytes,
        pidsLimit: container.pidsLimit,
        runtimeStatus: container.status || "running",
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
      cpuLimitCores: null,
      memoryLimitBytes: null,
      memoryReservationBytes: null,
      pidsLimit: null,
      runtimeStatus: "missing",
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
      diskComplete: disk.complete,
      diskTruncated: disk.truncated,
      diskStale: disk.stale,
      diskLimitReason: disk.reason,
      diskMeasuredAt: disk.measuredAt,
      symlinks: disk.symlinks,
      cpuCores,
      cpuPercent: sumContainerCpuPercent(exactContainers) ?? cpuPercent,
      memoryBytes,
      runtimeLimits: exactContainers.map((item) => ({
        container: item.name,
        cpuLimitCores: item.cpuLimitCores ?? null,
        memoryLimitBytes: item.memoryLimitBytes ?? null,
        memoryReservationBytes: item.memoryReservationBytes ?? null,
        pidsLimit: item.pidsLimit ?? null,
      })),
      cpuMessage: exactContainers.length ? "" : "Metriche container non disponibili",
      memoryMessage: exactContainers.length ? "" : "Metriche container non disponibili",
      containersLabel: exactContainers.length ? exactContainers.map((item) => item.name).join(", ") : `${dedicatedRuntimeName(project)} atteso`,
      measuredFrom: exactContainers.length ? `${exactContainers.some((item) => item.source === "docker-stats") ? "docker stats" : prometheus.containerSource || "Prometheus"} + filesystem` : "filesystem + container dedicato atteso",
      applications: projectApps.map((app) => app.id),
    });
  });
  const webspaceBytes = webspaces.reduce((sum, item) => sum + Number(item.usedBytes || 0), 0);
  const measuredProjectContainers = containersByProject.filter((item) => item.attribution === "container-dedicato" || item.attribution === "docker-stats");
  const containerMetricsAvailable = measuredProjectContainers.length > 0;
  const projectUsesPrometheus = measuredProjectContainers.some((item) => item.attribution === "container-dedicato");
  const projectUsesDockerStats = measuredProjectContainers.some((item) => item.attribution === "docker-stats");
  return sanitizeEvent({
    source: projectUsesPrometheus
      ? prometheus.containerSource || "prometheus-container-metrics"
      : projectUsesDockerStats
        ? `docker-stats-file (${dockerStats.capturedAt || "no timestamp"})`
        : prometheus.available ? "prometheus-node-exporter-host-only" : "local-filesystem",
    capturedAt: projectUsesPrometheus ? capturedAt : projectUsesDockerStats ? dockerStats.capturedAt || capturedAt : capturedAt,
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
    platformCollectorHealthy: "platform_container_metrics_collector_healthy",
    platformCollectorLastAttempt: "platform_container_metrics_collector_last_attempt_timestamp_seconds",
    platformContainerCpu: "platform_container_cpu_cores",
    platformContainerMemory: "platform_container_memory_usage_bytes",
    platformContainerCpuLimit: "platform_container_cpu_limit_cores",
    platformContainerMemoryLimit: "platform_container_memory_limit_bytes",
    platformContainerMemoryReservation: "platform_container_memory_reservation_bytes",
    platformContainerPidsLimit: "platform_container_pids_limit",
    cadvisorContainerCpuByName: 'sum by (name) (rate(container_cpu_usage_seconds_total{name!="",id!="/"}[2m]))',
    cadvisorContainerMemoryByName: 'max by (name) (container_memory_working_set_bytes{name!="",id!="/"})',
    cadvisorContainerCpuByContainer: 'sum by (container) (rate(container_cpu_usage_seconds_total{container!="",id!="/"}[2m]))',
    cadvisorContainerMemoryByContainer: 'max by (container) (container_memory_working_set_bytes{container!="",id!="/"})',
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
  const collectorHealthy = firstPrometheusValue(results.platformCollectorHealthy) === 1;
  const collectorLastAttempt = firstPrometheusValue(results.platformCollectorLastAttempt);
  const collectorFresh = collectorHealthy
    && Number.isFinite(collectorLastAttempt)
    && ((Date.now() / 1000) - collectorLastAttempt) >= 0
    && ((Date.now() / 1000) - collectorLastAttempt) <= (dockerStatsMaxAgeMs / 1000);
  const platformContainers = collectorFresh
    ? mergePrometheusContainerMetrics(
      results.platformContainerCpu,
      results.platformContainerMemory,
      "prometheus-node-exporter-textfile",
    )
    : [];
  attachPrometheusContainerLimit(platformContainers, results.platformContainerCpuLimit, "cpuLimitCores");
  attachPrometheusContainerLimit(platformContainers, results.platformContainerMemoryLimit, "memoryLimitBytes");
  attachPrometheusContainerLimit(platformContainers, results.platformContainerMemoryReservation, "memoryReservationBytes");
  attachPrometheusContainerLimit(platformContainers, results.platformContainerPidsLimit, "pidsLimit");
  const cadvisorContainers = mergePrometheusContainerMetrics(
    [...results.cadvisorContainerCpuByName, ...results.cadvisorContainerCpuByContainer],
    [...results.cadvisorContainerMemoryByName, ...results.cadvisorContainerMemoryByContainer],
    "prometheus-cadvisor-compatibility",
  );
  const containers = platformContainers.length ? platformContainers : cadvisorContainers;
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
    containerSource: platformContainers.length ? "prometheus-node-exporter-textfile" : cadvisorContainers.length ? "prometheus-cadvisor-compatibility" : "",
    containers,
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
    containerSource: "",
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

function mergePrometheusContainerMetrics(cpuRows, memoryRows, source = "prometheus") {
  const byName = new Map();
  for (const row of cpuRows) {
    const name = prometheusContainerName(row.metric || {});
    if (!name) continue;
    const current = byName.get(name) || prometheusContainerRecord(name, row.metric || {}, source);
    const value = firstPrometheusValue([row]);
    if (Number.isFinite(value)) {
      current.cpuCores = current.cpuCores == null ? value : Math.max(current.cpuCores, value);
      current.cpuPercent = current.cpuCores * 100;
    }
    byName.set(name, current);
  }
  for (const row of memoryRows) {
    const name = prometheusContainerName(row.metric || {});
    if (!name) continue;
    const current = byName.get(name) || prometheusContainerRecord(name, row.metric || {}, source);
    const value = firstPrometheusValue([row]);
    if (Number.isFinite(value)) current.memoryBytes = current.memoryBytes == null ? value : Math.max(current.memoryBytes, value);
    byName.set(name, current);
  }
  return [...byName.values()].filter((item) => item.cpuCores != null || item.memoryBytes != null);
}

function prometheusContainerRecord(name, metric, source) {
  return {
    name,
    service: sanitizeRef(metric.compose_service || ""),
    status: "running",
    source,
    cpuCores: null,
    cpuPercent: null,
    memoryBytes: null,
    cpuLimitCores: null,
    memoryLimitBytes: null,
    memoryReservationBytes: null,
    pidsLimit: null,
  };
}

function attachPrometheusContainerLimit(containers, rows, field) {
  const byName = new Map(containers.map((item) => [item.name, item]));
  for (const row of rows) {
    const name = prometheusContainerName(row.metric || {});
    const value = firstPrometheusValue([row]);
    if (!name || !Number.isFinite(value) || !byName.has(name)) continue;
    byName.get(name)[field] = value;
  }
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

async function readProjectDiskUsage(project) {
  if (!project.filesAvailable || !project.relativePath) return unavailableProjectDiskUsage("source-unavailable");
  try {
    const root = resolveProjectRoot(project);
    const key = `${project.slug}:${root}`;
    return await projectDiskUsageReader.read(key, root);
  } catch {
    return unavailableProjectDiskUsage("source-unavailable");
  }
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
  if (["go", "good", "active", "online", "running", "configured", "declared", "file", "directory", "passed", "success", "done", "completed"].includes(clean)) return "good";
  if (["warning", "warn", "pending", "queued", "accepted", "pending-live-proof", "pending-provider", "plan-only", "degraded", "local-estimate", "symlink"].includes(clean)) return "warn";
  if (["error", "failed", "critical", "needs-work", "disabled", "offline", "archived", "bad", "no-go"].includes(clean)) return "bad";
  return "info";
}

function renderLogin(message) {
  return `<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:,">
<title>Accesso Control Center</title>
${controlCenterStylesheetLinks()}
${controlCenterScriptTags()}
</head>
<body data-cc-theme="light">
<main class="login-shell">
  <section class="login-panel ui-panel-stack">
    <span class="brand-mark">P</span>
    <p class="eyebrow">${escapeHtml(environment.toUpperCase())}</p>
    <h1>Accesso amministrativo</h1>
    <p class="login-copy">${escapeHtml(message || "Autenticazione passkey richiesta.")}</p>
    <a class="button open" href="/auth/login">Accedi con passkey</a>
  </section>
</main>
</body>
</html>`;
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
  ownershipPolicy(() => assertManagedDatabaseName(engine, name));
  if (String(payload.ownerRole || "").trim()) throw new ValidationError("Database principals are generated server-side and cannot be supplied by the client.");
  const id = databaseId(projectId, engine, name);
  if (context.databases.some((database) => database.id === id || (database.engine === engine && database.name === name))) {
    throw new ValidationError("Database resource is already registered.");
  }
  const ownerRole = ownershipPolicy(() => generatedDatabasePrincipal({ projectId, engine, databaseName: name }));
  const displayName = sanitizeOptionalDescription(payload.displayName || "");
  const credential = prepareDatabaseCredentialUpdate(id, payload);
  const details = databaseRecord({
    id,
    projectId,
    engine,
    name,
    displayName,
    ownerRole,
    principalBindingId: id,
    principalManaged: true,
    principalBindingStatus: "reserved",
    ...credential.metadata,
  });
  if (payload.confirm === "CREATE-DATABASE") {
    const password = validateDatabasePasswordInput(payload.password || "");
    const state = readDatabasesState();
    if (state[id] && !state[id].deletedAt && state[id].status !== "deleted") throw new ValidationError("Database resource is already registered.");
    const registry = readDatabasePrincipalsState();
    const reservedBindings = ownershipPolicy(() => reservePrincipalBinding(registry.bindings, details));
    writeDatabasePrincipalsState({ ...registry, bindings: reservedBindings });
    const liveResult = applyLiveDatabaseCreate(details, password, reservedBindings);
    const writtenCredential = writeDatabaseCredentialIfProvided(id, payload);
    const principalBindingStatus = liveResult.applied ? "active" : "reserved";
    state[id] = {
      ...(state[id] || {}),
      ...details,
      ...writtenCredential.metadata,
      principalBindingStatus,
      status: liveResult.applied ? "active" : "declared",
      connectionStatus: liveResult.applied ? "configured" : "metadata-only",
      updatedAt: new Date().toISOString(),
      createdAt: state[id]?.createdAt || new Date().toISOString(),
    };
    writeDatabasesState(state);
    if (liveResult.applied) {
      writeDatabasePrincipalsState({ ...registry, bindings: ownershipPolicy(() => activatePrincipalBinding(reservedBindings, details)) });
    }
    appendAudit({ action: "database.create.apply", target: `${projectId}/${name}`, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: liveResult.applied ? "Database and its server-generated principal were created under an exact ownership binding; the credential value was not exposed." : "Database metadata and a reserved server-generated principal binding were stored; live adapter disabled." });
    const operation = operationPlan("database.create.local", context.environment, false, ["validate project and protected database denylist", "generate project-scoped principal", "reserve exact ownership binding", "verify catalog has no colliding database or principal", "create database and principal when live adapter is enabled", "grant only target database permissions", "store protected credential", "write audit event"], { ...state[id], databaseId: id, databaseTouched: liveResult.applied, dataChanged: liveResult.applied, credentialsExposed: false, credentialValueStored: writtenCredential.written, opensAdminDatabase: false, liveAdapter: liveResult.mode, productionEvidence: false });
    return { ...operation, database: state[id] };
  }
  appendAudit({ action: "database.create.plan", target: `${projectId}/${name}`, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Database creation plan generated; no live database mutation executed." });
  return operationPlan("database.create", context.environment, true, ["validate project and database name", "generate project-scoped principal", "prepare exact ownership reservation", "require apply confirmation", "write audit event"], { ...details, databaseTouched: false, credentialsExposed: false, productionEvidence: false, confirmationRequired: "CREATE-DATABASE" });
}

function prepareDatabaseCredentialUpdate(databaseId, payload = {}) {
  const password = String(payload.password || "");
  const credentialRef = databaseCredentialRef(databaseId);
  const hasPassword = password.length > 0;
  if (hasPassword) validateDatabasePasswordInput(password);
  return {
    hasPassword,
    metadata: {
      credentialRef,
      credentialFile: hasPassword ? databaseCredentialFilePath(databaseId) : "",
      credentialStatus: hasPassword ? "secret-file-set" : "protected",
      credentialUpdatedAt: hasPassword ? new Date().toISOString() : null,
    },
  };
}

function writeDatabaseCredentialIfProvided(databaseId, payload = {}) {
  const password = String(payload.password || "");
  const credentialRef = databaseCredentialRef(databaseId);
  if (!password) {
    return {
      written: false,
      metadata: {
        credentialRef,
        credentialStatus: "protected",
      },
    };
  }
  validateDatabasePasswordInput(password);
  const filePath = databaseCredentialFilePath(databaseId);
  mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  writeFileSync(filePath, `${password}\n`, { mode: 0o600 });
  return {
    written: true,
    metadata: {
      credentialRef,
      credentialFile: filePath,
      credentialStatus: "secret-file-set",
      credentialUpdatedAt: new Date().toISOString(),
    },
  };
}

function databaseCredentialFilePath(databaseId) {
  const cleanId = sanitizeIdentifier(databaseId);
  if (!cleanId) throw new ValidationError("Database credential id non valido.");
  return path.join(databaseCredentialDir, `${cleanId}.txt`);
}

function databaseCredentialRef(databaseId) {
  const cleanId = sanitizeIdentifier(databaseId);
  if (!cleanId) throw new ValidationError("Database credential id non valido.");
  return `secret/db/${cleanId}`;
}

function validateDatabasePasswordInput(value) {
  const password = String(value || "");
  if (!password) throw new ValidationError("Password database richiesta.");
  if (password.length > 4096 || password.includes("\0")) throw new ValidationError("Password database non valida.");
  return password;
}

function applyLiveDatabaseCreate(database, password, registry) {
  if (!databaseLiveApply) return { applied: false, mode: "metadata-only" };
  if (database.engine === "postgres") return applyLivePostgresCreate(database, password, registry);
  return applyLiveMariaDbCreate(database, password, registry);
}

function applyLiveDatabaseCredential(database, password, registry) {
  if (!databaseLiveApply) return { applied: false, mode: "metadata-only", action: "none" };
  const binding = principalBindingFor(registry, database);
  if (!binding) throw new RejectedOperationError("Database principal has no exact managed ownership binding.");
  if (binding.status === "reserved") return applyLiveDatabaseCreate(database, password, registry);
  if (binding.status !== "active") throw new RejectedOperationError("Database principal binding is not active.");
  if (database.engine === "postgres") return applyLivePostgresCredential(database, password, registry);
  return applyLiveMariaDbCredential(database, password, registry);
}

function applyLiveDatabaseDelete(database, state = {}, registry = {}) {
  if (!databaseLiveApply) return { applied: false, mode: "metadata-only" };
  if (database.engine === "postgres") return applyLivePostgresDelete(database, state, registry);
  return applyLiveMariaDbDelete(database, state, registry);
}

function applyLiveDatabasePrincipalCleanup(database, state = {}, registry = {}) {
  if (!databaseLiveApply || !databaseOwnerRoleIsExclusive(database, state, registry)) {
    return { applied: false, mode: databaseLiveApply ? "shared-principal-preserved" : "metadata-only" };
  }
  if (database.engine === "postgres") return applyLivePostgresPrincipalCleanup(database, registry);
  return applyLiveMariaDbPrincipalCleanup(database, registry);
}

function applyLiveMariaDbCreate(database, password, registry) {
  const rootPassword = readRequiredSecretFile(mariadbRootPasswordFile, "MariaDB root password");
  const catalog = inspectMariaDbOwnership(database, rootPassword);
  ownershipPolicy(() => assertPrincipalCreateAllowed({ database, registry, catalog }), RejectedOperationError);
  const sql = [
    `CREATE USER ${mysqlUserHost(database.ownerRole)} IDENTIFIED BY ${mysqlStringLiteral(password)}`,
    `CREATE DATABASE ${mysqlIdentifier(database.name)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`,
    `GRANT ALL PRIVILEGES ON ${mysqlIdentifier(database.name)}.* TO ${mysqlUserHost(database.ownerRole)}`,
    "FLUSH PRIVILEGES",
  ].join(";\n") + ";\n";
  runDatabaseClient("mariadb", [
    "--protocol=TCP",
    "-h", mariadbHost,
    "-P", String(mariadbPort),
    "-u", mariadbRootUser,
    "--batch",
    "--skip-column-names",
  ], {
    input: sql,
    env: { MYSQL_PWD: rootPassword },
    label: "MariaDB create database",
  });
  return { applied: true, mode: "mariadb-cli", action: "provision" };
}

function applyLiveMariaDbCredential(database, password, registry) {
  const rootPassword = readRequiredSecretFile(mariadbRootPasswordFile, "MariaDB root password");
  const catalog = inspectMariaDbOwnership(database, rootPassword);
  ownershipPolicy(() => assertPrincipalRotationAllowed({ database, registry, catalog }), RejectedOperationError);
  runDatabaseClient("mariadb", [
    "--protocol=TCP",
    "-h", mariadbHost,
    "-P", String(mariadbPort),
    "-u", mariadbRootUser,
    "--batch",
    "--skip-column-names",
  ], {
    input: `ALTER USER ${mysqlUserHost(database.ownerRole)} IDENTIFIED BY ${mysqlStringLiteral(password)};\n`,
    env: { MYSQL_PWD: rootPassword },
    label: "MariaDB rotate managed database credential",
  });
  return { applied: true, mode: "mariadb-cli", action: "rotate" };
}

function applyLiveMariaDbDelete(database, state = {}, registry = {}) {
  const rootPassword = readRequiredSecretFile(mariadbRootPasswordFile, "MariaDB root password");
  const catalog = inspectMariaDbOwnership(database, rootPassword);
  ownershipPolicy(() => assertPrincipalDeletionAllowed({ database, registry, catalog }), RejectedOperationError);
  runDatabaseClient("mariadb", [
    "--protocol=TCP",
    "-h", mariadbHost,
    "-P", String(mariadbPort),
    "-u", mariadbRootUser,
    "--batch",
    "--skip-column-names",
  ], {
    input: `DROP DATABASE IF EXISTS ${mysqlIdentifier(database.name)};\n`,
    env: { MYSQL_PWD: rootPassword },
    label: "MariaDB drop database",
  });
  return { applied: true, mode: "mariadb-cli", principalCleanupRequired: databaseOwnerRoleIsExclusive(database, state, registry) };
}

function applyLiveMariaDbPrincipalCleanup(database, registry = {}) {
  const rootPassword = readRequiredSecretFile(mariadbRootPasswordFile, "MariaDB root password");
  const catalog = inspectMariaDbOwnership(database, rootPassword);
  ownershipPolicy(() => assertPrincipalCleanupAllowed({ database, registry, catalog }), RejectedOperationError);
  runDatabaseClient("mariadb", [
    "--protocol=TCP",
    "-h", mariadbHost,
    "-P", String(mariadbPort),
    "-u", mariadbRootUser,
    "--batch",
    "--skip-column-names",
  ], {
    input: `DROP USER IF EXISTS ${mysqlUserHost(database.ownerRole)};\nFLUSH PRIVILEGES;\n`,
    env: { MYSQL_PWD: rootPassword },
    label: "MariaDB drop managed database principal",
  });
  return { applied: true, mode: "mariadb-cli" };
}

function applyLivePostgresCreate(database, password, registry) {
  const superPassword = readRequiredSecretFile(postgresSuperuserPasswordFile, "PostgreSQL superuser password");
  const catalog = inspectPostgresOwnership(database, superPassword);
  ownershipPolicy(() => assertPrincipalCreateAllowed({ database, registry, catalog }), RejectedOperationError);
  const databaseSql = [
    `CREATE ROLE ${postgresIdentifier(database.ownerRole)} LOGIN PASSWORD ${postgresStringLiteral(password)};`,
    `CREATE DATABASE ${postgresIdentifier(database.name)} OWNER ${postgresIdentifier(database.ownerRole)};`,
    `GRANT ALL PRIVILEGES ON DATABASE ${postgresIdentifier(database.name)} TO ${postgresIdentifier(database.ownerRole)};`,
  ].join("\n") + "\n";
  runPostgresSql(databaseSql, superPassword, "PostgreSQL create database");
  return { applied: true, mode: "postgres-cli", action: "provision" };
}

function applyLivePostgresCredential(database, password, registry) {
  const superPassword = readRequiredSecretFile(postgresSuperuserPasswordFile, "PostgreSQL superuser password");
  const catalog = inspectPostgresOwnership(database, superPassword);
  ownershipPolicy(() => assertPrincipalRotationAllowed({ database, registry, catalog }), RejectedOperationError);
  runPostgresSql(`ALTER ROLE ${postgresIdentifier(database.ownerRole)} LOGIN PASSWORD ${postgresStringLiteral(password)};\n`, superPassword, "PostgreSQL rotate managed database credential");
  return { applied: true, mode: "postgres-cli", action: "rotate" };
}

function applyLivePostgresDelete(database, state = {}, registry = {}) {
  const superPassword = readRequiredSecretFile(postgresSuperuserPasswordFile, "PostgreSQL superuser password");
  const catalog = inspectPostgresOwnership(database, superPassword);
  ownershipPolicy(() => assertPrincipalDeletionAllowed({ database, registry, catalog }), RejectedOperationError);
  const dropSql = [
    `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = ${postgresStringLiteral(database.name)};`,
    `DROP DATABASE IF EXISTS ${postgresIdentifier(database.name)} WITH (FORCE);`,
  ];
  runPostgresSql(`${dropSql.join("\n")}\n`, superPassword, "PostgreSQL drop database");
  return { applied: true, mode: "postgres-cli", principalCleanupRequired: databaseOwnerRoleIsExclusive(database, state, registry) };
}

function applyLivePostgresPrincipalCleanup(database, registry = {}) {
  const superPassword = readRequiredSecretFile(postgresSuperuserPasswordFile, "PostgreSQL superuser password");
  const catalog = inspectPostgresOwnership(database, superPassword);
  ownershipPolicy(() => assertPrincipalCleanupAllowed({ database, registry, catalog }), RejectedOperationError);
  runPostgresSql(`DROP ROLE IF EXISTS ${postgresIdentifier(database.ownerRole)};\n`, superPassword, "PostgreSQL drop managed database principal");
  return { applied: true, mode: "postgres-cli" };
}

function inspectMariaDbOwnership(database, rootPassword) {
  const args = [
    "--protocol=TCP",
    "-h", mariadbHost,
    "-P", String(mariadbPort),
    "-u", mariadbRootUser,
    "--batch",
    "--skip-column-names",
  ];
  const env = { MYSQL_PWD: rootPassword };
  const hosts = databaseClientLines(runDatabaseClient("mariadb", args, {
    input: `SELECT Host FROM mysql.user WHERE User = ${mysqlStringLiteral(database.ownerRole)} ORDER BY Host;\n`,
    env,
    label: "MariaDB inspect principal",
  }));
  const databaseExists = databaseClientLines(runDatabaseClient("mariadb", args, {
    input: `SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ${mysqlStringLiteral(database.name)};\n`,
    env,
    label: "MariaDB inspect database",
  }))[0] === "1";
  const grants = hosts.includes("%") ? databaseClientLines(runDatabaseClient("mariadb", args, {
    input: `SHOW GRANTS FOR ${mysqlUserHost(database.ownerRole)};\n`,
    env,
    label: "MariaDB inspect principal grants",
  })) : [];
  const ownsDatabase = grants.some((line) => line.replaceAll("`", "").toLowerCase().includes(`on ${database.name.toLowerCase()}.* to`));
  const globalAdmin = grants.some((line) => /GRANT\s+(?!USAGE\b).+\s+ON\s+\*\.\*/i.test(line));
  return {
    principal: {
      exists: hosts.length > 0,
      admin: globalAdmin,
      grantOption: grants.some((line) => /WITH GRANT OPTION/i.test(line)),
      identityMismatch: hosts.length !== 1 || hosts[0] !== "%",
    },
    database: {
      exists: databaseExists,
      owner: databaseExists && ownsDatabase ? database.ownerRole : "",
    },
  };
}

function inspectPostgresOwnership(database, superPassword) {
  const roleLine = databaseClientLines(runPostgresSql([
    "SELECT concat_ws('|', rolname,",
    "  CASE WHEN rolsuper THEN '1' ELSE '0' END,",
    "  CASE WHEN rolcreaterole THEN '1' ELSE '0' END,",
    "  CASE WHEN rolcreatedb THEN '1' ELSE '0' END,",
    "  CASE WHEN rolreplication THEN '1' ELSE '0' END,",
    "  CASE WHEN rolbypassrls THEN '1' ELSE '0' END)",
    `FROM pg_roles WHERE rolname = ${postgresStringLiteral(database.ownerRole)};`,
  ].join("\n"), superPassword, "PostgreSQL inspect principal"))[0] || "";
  const role = roleLine ? roleLine.split("|") : [];
  const owner = databaseClientLines(runPostgresSql(
    `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = ${postgresStringLiteral(database.name)};\n`,
    superPassword,
    "PostgreSQL inspect database",
  ))[0] || "";
  return {
    principal: {
      exists: role.length === 6,
      superuser: role[1] === "1",
      createRole: role[2] === "1",
      createDb: role[3] === "1",
      replication: role[4] === "1",
      bypassRls: role[5] === "1",
    },
    database: {
      exists: Boolean(owner),
      owner,
    },
  };
}

function runPostgresSql(sql, password, label) {
  return runDatabaseClient("psql", [
    "-h", postgresHost,
    "-p", String(postgresPort),
    "-U", postgresSuperuser,
    "-d", "postgres",
    "-v", "ON_ERROR_STOP=1",
    "-A",
    "-t",
    "-q",
  ], {
    input: sql,
    env: { PGPASSWORD: password },
    label,
  });
}

function runDatabaseClient(command, args, { input = "", env = {}, label = "database command" } = {}) {
  const result = spawnSync(command, args, {
    input,
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 20000,
    maxBuffer: 1024 * 1024,
  });
  if (result.error?.code === "ENOENT") throw new RejectedOperationError(`${label}: client database non disponibile nel Control Center.`);
  if (result.error) throw new RejectedOperationError(`${label}: ${sanitizeDatabaseClientError(result.error.message)}`);
  if (result.status !== 0) throw new RejectedOperationError(`${label}: ${sanitizeDatabaseClientError(result.stderr || result.stdout || "comando fallito")}`);
  return String(result.stdout || "");
}

function databaseClientLines(value) {
  return String(value || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function readRequiredSecretFile(filePath, label) {
  const value = String(filePath || "").trim();
  if (!value) throw new RejectedOperationError(`${label}: secret non montato nel Control Center.`);
  const resolved = path.resolve(value);
  if (!resolved.startsWith("/run/secrets/")) throw new RejectedOperationError(`${label}: path secret non ammesso.`);
  try {
    const secret = readFileSync(resolved, "utf8").trim();
    if (!secret) throw new Error("empty secret");
    return secret;
  } catch {
    throw new RejectedOperationError(`${label}: secret non leggibile.`);
  }
}

function databaseOwnerRoleIsExclusive(database, state = {}, registry = {}) {
  const owner = sanitizeDatabasePrincipal(database.ownerRole || "");
  if (!owner) return false;
  const binding = principalBindingFor(registry, database);
  if (!binding || binding.status !== "active" || binding.principalName !== owner) return false;
  return !Object.values(state || {}).some((candidate) => candidate
    && candidate.id !== database.id
    && !candidate.deletedAt
    && candidate.status !== "deleted"
    && candidate.engine === database.engine
    && sanitizeDatabasePrincipal(candidate.ownerRole || "") === owner);
}

function removeDatabaseCredentialFile(database) {
  const candidates = new Set();
  if (database.credentialFile) candidates.add(database.credentialFile);
  try {
    candidates.add(databaseCredentialFilePath(database.id));
  } catch {
    // Ignore invalid legacy IDs.
  }
  for (const candidate of candidates) {
    const safePath = sanitizeCredentialFilePath(candidate);
    if (safePath && existsSync(safePath)) rmSync(safePath, { force: true });
  }
}

function mysqlIdentifier(value) {
  return `\`${validateDatabaseName(value).replace(/`/g, "``")}\``;
}

function mysqlStringLiteral(value) {
  return `'${String(value || "").replace(/\\/g, "\\\\").replace(/'/g, "''")}'`;
}

function mysqlUserHost(user) {
  return `${mysqlStringLiteral(validateDatabaseName(user))}@'%'`;
}

function postgresIdentifier(value) {
  return `"${validateDatabaseName(value).replace(/"/g, "\"\"")}"`;
}

function postgresStringLiteral(value) {
  return `'${String(value || "").replace(/'/g, "''")}'`;
}

function sanitizeDatabaseClientError(message) {
  return sanitizeMessage(String(message || "").replace(/\s+/g, " ").trim()).slice(0, 240) || "comando database fallito";
}

function ownershipPolicy(operation, ErrorType = ValidationError) {
  try {
    return operation();
  } catch (error) {
    if (error instanceof DatabaseOwnershipError) throw new ErrorType(error.message);
    throw error;
  }
}

function planDatabaseUpdate(id, payload, context) {
  const database = findById(context.databases, id, "Database");
  const displayName = sanitizeOptionalDescription(payload.displayName || database.displayName || "");
  if (String(payload.ownerRole || "").trim() && validateDatabaseName(payload.ownerRole) !== database.ownerRole) {
    throw new ValidationError("Database principal ownership is immutable; use the controlled migration workflow.");
  }
  const ownerRole = database.ownerRole;
  const status = choice(String(payload.status || database.status || "declared"), ["declared", "active", "maintenance", "disabled"], "database status");
  const connectionStatus = choice(String(payload.connectionStatus || database.connectionStatus || "metadata-only"), ["metadata-only", "configured", "healthy", "needs-check", "disabled"], "database connection status");
  const credentialRef = databaseCredentialRef(database.id);
  const details = databaseRecord({
    ...database,
    displayName,
    ownerRole,
    status,
    connectionStatus,
    credentialRef,
    credentialStatus: database.credentialStatus || (credentialRef ? "secret-ref-set" : "protected"),
  });
  const confirmation = `UPDATE-DATABASE:${database.id}`;
  if (payload.confirm === confirmation) {
    const state = readDatabasesState();
    state[database.id] = {
      ...(state[database.id] || database),
      ...details,
      updatedAt: new Date().toISOString(),
      deletedAt: null,
    };
    writeDatabasesState(state);
    appendAudit({ action: "database.update.apply", target: database.id, environment: context.environment, risk: "medium", result: "success", dryRun: false, summary: "Database metadata updated locally; live database and credentials were not mutated." });
    const operation = operationPlan("database.update.local", context.environment, false, ["validate database", "update metadata", "preserve live database", "preserve credential value", "write audit event"], { ...state[database.id], databaseId: database.id, databaseTouched: false, credentialsExposed: false, productionEvidence: false });
    return { ...operation, database: state[database.id] };
  }
  appendAudit({ action: "database.update.plan", target: database.id, environment: context.environment, risk: "medium", result: "planned", dryRun: true, summary: "Database metadata update plan generated; no live database mutation executed." });
  return operationPlan("database.update", context.environment, true, ["validate database", "prepare metadata update", "require explicit confirmation", "preserve credential value", "write audit event"], { ...details, databaseId: database.id, databaseTouched: false, credentialsExposed: false, productionEvidence: false, confirmationRequired: confirmation });
}

function planDatabaseCredentialUpdate(id, payload, context) {
  const database = findById(context.databases, id, "Database");
  const credentialRef = databaseCredentialRef(database.id);
  const credential = prepareDatabaseCredentialUpdate(database.id, payload);
  const confirmation = `ROTATE-DATABASE-CREDENTIAL:${database.id}`;
  if (payload.confirm === confirmation) {
    const state = readDatabasesState();
    const registry = readDatabasePrincipalsState();
    const password = validateDatabasePasswordInput(payload.password || "");
    const liveResult = applyLiveDatabaseCredential(database, password, registry.bindings);
    const writtenCredential = writeDatabaseCredentialIfProvided(database.id, payload);
    let bindings = registry.bindings;
    if (liveResult.applied && liveResult.action === "provision") {
      bindings = ownershipPolicy(() => activatePrincipalBinding(bindings, database));
      writeDatabasePrincipalsState({ ...registry, bindings });
    }
    const binding = principalBindingFor(bindings, database);
    state[database.id] = {
      ...(state[database.id] || database),
      credentialRef,
      ...writtenCredential.metadata,
      principalManaged: Boolean(binding),
      principalBindingId: binding?.databaseId || database.principalBindingId || "",
      principalBindingStatus: binding?.status || database.principalBindingStatus || "legacy-unbound",
      credentialStatus: writtenCredential.written ? "secret-file-set" : credentialRef ? "rotation-requested-secret-ref" : "rotation-requested",
      credentialUpdatedAt: new Date().toISOString(),
      credentialsExposed: false,
      databaseTouched: liveResult.applied,
      connectionStatus: liveResult.applied ? "configured" : database.connectionStatus,
      status: liveResult.applied ? "active" : database.status,
      updatedAt: new Date().toISOString(),
    };
    writeDatabasesState(state);
    appendAudit({ action: "database.credential.update.apply", target: database.id, environment: context.environment, risk: "high", result: "success", dryRun: false, summary: writtenCredential.written ? "Credential updated only after exact principal ownership and non-privileged catalog verification; value not exposed." : "Database credential rotation request recorded without storing or exposing the credential value." });
    const operation = operationPlan("database.credential.local", context.environment, false, ["validate exact principal ownership", "verify catalog principal is non-privileged", "rotate only the bound principal", "write protected credential after successful live mutation", "keep plaintext out of state and HTML", "write audit event"], { ...state[database.id], databaseId: database.id, databaseTouched: liveResult.applied, dataChanged: liveResult.applied, credentialsExposed: false, credentialValueStored: writtenCredential.written, liveAdapter: liveResult.mode, productionEvidence: false });
    return { ...operation, database: state[database.id] };
  }
  appendAudit({ action: "database.credential.update.plan", target: database.id, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Database credential rotation plan generated without exposing the credential value." });
  return operationPlan("database.credential", context.environment, true, ["validate database", "prepare credential rotation request", "require explicit confirmation", "do not store plaintext", "write audit event"], { databaseId: database.id, projectId: database.projectId, engine: database.engine, credentialRef, credentialFile: credential.metadata.credentialFile || database.credentialFile || "", databaseTouched: false, credentialsExposed: false, credentialValueStored: false, productionEvidence: false, confirmationRequired: confirmation });
}

function planDatabaseDelete(id, payload, context) {
  const database = findById(context.databases, id, "Database");
  const confirmation = databaseDeleteConfirmation(database, "REQUEST");
  const restorePoint = findDatabaseDeleteRestorePoint({ database, backupRoot, reportsRoot, maxAgeMs: databaseDeleteEvidenceMaxAgeMs });
  if (payload.confirm !== confirmation) {
    appendAudit({ action: "database.delete.plan", target: database.id, environment: context.environment, risk: "high", result: "planned", dryRun: true, summary: "Database delete plan generated; exact fresh local/off-site backup and restore drill are mandatory." });
    return operationPlan("database.delete", context.environment, true, ["type the exact database name", "verify exact signed backup manifest", "verify exact disposable restore drill", "verify fresh off-site snapshot receipt", "create idempotent delete request", "approve in a separate owner action", "execute through the checkpointed state machine"], {
      databaseId: database.id,
      projectId: database.projectId,
      engine: database.engine,
      name: database.name,
      databaseTouched: false,
      dataDeleted: false,
      credentialsExposed: false,
      backupRequiredBeforeLiveDelete: true,
      restorePointReady: restorePoint.ready,
      evidenceBlockers: restorePoint.blockers,
      productionEvidence: false,
      confirmationRequired: confirmation,
      typedNameRequired: database.name,
    });
  }
  if (String(payload.typedName || "") !== database.name) throw new RejectedOperationError(`Type the exact database name '${database.name}' to request deletion.`);
  const idempotencyKey = String(payload.idempotencyKey || "").trim();
  if (!idempotencyKey) throw new RejectedOperationError("Database delete request requires an idempotency key.");
  const state = readDatabaseDeleteOperationsState();
  const existing = Object.values(state.operations).find((operation) => operation.idempotencyKey === idempotencyKey);
  if (existing) {
    const parsed = parseDatabaseDeleteOperation(existing);
    if (parsed.database.id !== database.id) throw new RejectedOperationError("Idempotency key is already bound to another database.");
    return databaseDeleteOperationResponse("database.delete.requested", parsed, context, true);
  }
  if (!restorePoint.ready) throw new RejectedOperationError(`Database delete blocked: ${restorePoint.blockers.join(", ")}.`);
  const identity = requestIdentity.getStore();
  const operation = createDatabaseDeleteOperation({
    id: rid(),
    database,
    evidence: restorePoint.evidence,
    idempotencyKey,
    requestedBy: identity?.subject || "unknown-admin",
  });
  state.operations[operation.id] = operation;
  writeDatabaseDeleteOperationsState(state);
  appendAudit({ action: "database.delete.request", actor: identity?.subject, target: database.id, environment: context.environment, risk: "high", result: "accepted", dryRun: false, summary: "Checkpointed database delete request created after exact backup, restore and off-site evidence verification." });
  return databaseDeleteOperationResponse("database.delete.requested", operation, context, false);
}

function approveDatabaseDelete(operationId, payload, context) {
  const state = readDatabaseDeleteOperationsState();
  const operation = findDatabaseDeleteOperation(state, operationId);
  const database = findById(context.databases, operation.database.id, "Database");
  if (payload.confirm !== databaseDeleteConfirmation(database, "APPROVE", operation.id)) throw new RejectedOperationError("Database delete approval confirmation is invalid.");
  if (String(payload.typedName || "") !== database.name) throw new RejectedOperationError(`Type the exact database name '${database.name}' to approve deletion.`);
  if (operation.status === "approved") return databaseDeleteOperationResponse("database.delete.approved", operation, context, true);
  if (!new Set(["evidence-verified", "failed"]).has(operation.status)) throw new RejectedOperationError(`Database delete cannot be approved from state ${operation.status}.`);
  const restorePoint = findDatabaseDeleteRestorePoint({ database, backupRoot, reportsRoot, maxAgeMs: databaseDeleteEvidenceMaxAgeMs });
  if (!restorePoint.ready || restorePoint.evidence.fingerprint !== operation.evidenceFingerprint) throw new RejectedOperationError("Database delete evidence changed, expired or is no longer complete. Create a new request.");
  const identity = requestIdentity.getStore();
  const approved = transitionDatabaseDeleteOperation(operation, "approved", { approvedBy: identity?.subject || "unknown-admin" });
  state.operations[approved.id] = approved;
  writeDatabaseDeleteOperationsState(state);
  appendAudit({ action: "database.delete.approve", actor: identity?.subject, target: database.id, environment: context.environment, risk: "high", result: "approved", dryRun: false, summary: "Database delete approved in a separate fresh owner action; no data changed." });
  return databaseDeleteOperationResponse("database.delete.approved", approved, context, false);
}

function executeDatabaseDelete(operationId, payload, context) {
  const operationState = readDatabaseDeleteOperationsState();
  const operation = findDatabaseDeleteOperation(operationState, operationId);
  if (operation.status === "completed") return databaseDeleteOperationResponse("database.delete.completed", operation, context, true);
  if (operation.status !== "approved") throw new RejectedOperationError(`Database delete execution requires approved state, not ${operation.status}.`);
  if (payload.confirm !== databaseDeleteConfirmation(operation.database, "EXECUTE", operation.id)) throw new RejectedOperationError("Database delete execution confirmation is invalid.");
  if (String(payload.typedName || "") !== operation.database.name) throw new RejectedOperationError(`Type the exact database name '${operation.database.name}' to execute deletion.`);
  if (!databaseLiveApply) throw new RejectedOperationError("Database delete executor is disabled; metadata and credentials were preserved.");

  const databases = readDatabasesState();
  const database = databases[operation.database.id];
  if (!database || database.engine !== operation.database.engine || database.name !== operation.database.name || database.projectId !== operation.database.projectId) {
    throw new RejectedOperationError("Database metadata no longer matches the approved delete operation.");
  }
  const restorePoint = findDatabaseDeleteRestorePoint({ database, backupRoot, reportsRoot, maxAgeMs: databaseDeleteEvidenceMaxAgeMs });
  if (!restorePoint.ready || restorePoint.evidence.fingerprint !== operation.evidenceFingerprint) throw new RejectedOperationError("Database delete evidence changed, expired or is no longer complete.");

  const registry = readDatabasePrincipalsState();
  let current = transitionDatabaseDeleteOperation(operation, "executing");
  operationState.operations[current.id] = current;
  writeDatabaseDeleteOperationsState(operationState);
  let databaseDropped = false;
  try {
    const liveResult = applyLiveDatabaseDelete(database, databases, registry.bindings);
    if (!liveResult.applied) throw new RejectedOperationError("Database delete executor did not apply a live database change.");
    databaseDropped = true;
    current = transitionDatabaseDeleteOperation(current, "database-dropped");
    operationState.operations[current.id] = current;
    writeDatabaseDeleteOperationsState(operationState);

    const principalCleanup = applyLiveDatabasePrincipalCleanup(database, databases, registry.bindings);
    removeDatabaseCredentialFile(database);
    delete databases[database.id];
    writeDatabasesState(databases);
    const binding = principalBindingFor(registry.bindings, database);
    if (binding) {
      const bindings = { ...registry.bindings };
      delete bindings[database.id];
      writeDatabasePrincipalsState({ ...registry, bindings });
    }
    current = transitionDatabaseDeleteOperation(current, "completed");
    operationState.operations[current.id] = current;
    writeDatabaseDeleteOperationsState(operationState);
    const identity = requestIdentity.getStore();
    appendAudit({ action: "database.delete.complete", actor: identity?.subject, target: database.id, environment: context.environment, risk: "high", result: "success", dryRun: false, summary: "Exact managed database, principal, metadata and protected credential removed through the checkpointed workflow." });
    return databaseDeleteOperationResponse("database.delete.completed", current, context, false, { ...liveResult, principalCleanup });
  } catch (error) {
    try {
      if (databaseDropped && current.status === "executing") current = transitionDatabaseDeleteOperation(current, "database-dropped");
      current = transitionDatabaseDeleteOperation(current, databaseDropped ? "rollback-required" : "failed", { failure: sanitizeDatabaseClientError(error?.message || error) });
      operationState.operations[current.id] = current;
      writeDatabaseDeleteOperationsState(operationState);
    } catch {
      // Preserve the original failure; the last durable checkpoint remains available for reconciliation.
    }
    appendAudit({ action: "database.delete.failed", target: operation.database.id, environment: context.environment, risk: "high", result: databaseDropped ? "rollback-required" : "failed", dryRun: false, summary: databaseDropped ? "Database drop completed but cleanup failed; automatic retry stopped and restore/finalize approval is required." : "Database delete stopped before the database drop completed." });
    if (error instanceof RejectedOperationError) throw error;
    throw new RejectedOperationError(`Database delete failed in state ${databaseDropped ? "rollback-required" : "failed"}.`);
  }
}

function databaseDeleteOperationResponse(type, operation, context, idempotent = false, liveResult = null) {
  const publicOperation = {
    ...operation,
    database: { ...operation.database, credentialFile: "" },
  };
  return {
    ...operationPlan(type, context.environment, false, ["preserve exact evidence fingerprint", "persist every destructive checkpoint", "never auto-retry after database drop"], {
      databaseId: operation.database.id,
      projectId: operation.database.projectId,
      engine: operation.database.engine,
      name: operation.database.name,
      operationId: operation.id,
      operationStatus: operation.status,
      resourceId: operation.resourceId,
      evidenceFingerprint: operation.evidenceFingerprint,
      backupRequiredBeforeLiveDelete: true,
      restorePointReady: true,
      databaseTouched: operation.status === "completed",
      dataDeleted: operation.status === "completed",
      credentialsExposed: false,
      liveAdapter: liveResult?.mode || (databaseLiveApply ? "enabled" : "disabled"),
      idempotent,
      productionEvidence: false,
    }),
    deleteOperation: publicOperation,
    database: operation.status === "completed" ? null : publicOperation.database,
  };
}

function findDatabaseDeleteOperation(state, operationId) {
  const cleanId = sanitizeIdentifier(operationId);
  if (!cleanId || !state.operations[cleanId]) throw new ValidationError("Database delete operation not found.");
  return parseDatabaseDeleteOperation(state.operations[cleanId]);
}

function planDatabaseBackup(id, payload, context) {
  const database = findById(context.databases, id, "Database");
  const scope = `database:${database.id}`;
  const resource = {
    id: backupResourceId("database", database.id),
    externalId: database.id,
    kind: "database",
    projectId: database.projectId || "platform",
    name: database.name,
    engine: database.engine,
  };
  const job = createBackupJob({
    operation: "backup",
    scope: database.projectId ? { kind: "application", id: database.projectId } : { kind: "platform", id: "platform" },
    resources: [resource],
    context,
  });
  appendAudit({ action: "database.backup.queue", target: database.id, environment: context.environment, risk: "medium", result: "accepted", dryRun: false, summary: "Exact database backup queued for the typed backup executor." });
  const operation = operationPlan("database.backup", context.environment, false, ["validate exact database resource", "write versioned typed job", "dump only the selected database", "write signed manifest"], {
    databaseId: database.id,
    projectId: database.projectId,
    engine: database.engine,
    scope,
    jobId: job.id,
    resourceId: resource.id,
    databaseTouched: false,
    credentialsExposed: false,
    productionEvidence: false,
  });
  const backup = backupRecord({
    operationId: operation.id,
    jobId: job.id,
    action: "backup",
    scope,
    environment: context.environment,
    status: "queued",
    dryRun: false,
    resultSummary: `Backup database ${database.id} accodato con identita' risorsa esatta.`,
  });
  appendBackupRecord(backup);
  return { ...operation, database, backup, job };
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

function planVaultSecretCreate(payload, context) {
  const projectId = validateProjectOrPlatform(payload.projectId || "platform", context);
  const targetEnv = normalizeEnvironment(payload.targetEnv || payload.environment || context.environment);
  const itemKey = validateVaultItemKey(payload.itemKey || payload.name || "");
  const kind = choice(String(payload.kind || payload.materialKind || "application"), ["application", "docker", "provider", "kms", "database", "storage"], "vault item kind");
  const id = vaultItemId(projectId, targetEnv, itemKey);
  const rawValue = String(payload.value || payload.plainValue || "");
  const details = vaultItemRecord({
    id,
    itemKey,
    label: payload.label || humanName(itemKey),
    projectId,
    environment: targetEnv,
    kind,
    username: payload.username || "",
    url: payload.url || "",
    rotationDays: payload.rotationDays || 90,
    valueStored: false,
    valueFingerprint: rawValue ? sha256(rawValue) : "",
    source: "control-center-vault",
  });
  if (payload.confirm === "STORE-VAULT-SECRET") {
    if (!rawValue) throw new ValidationError("Vault value is required.");
    const state = readVaultState();
    const previous = state.items[id] || {};
    const now = new Date().toISOString();
    const item = vaultItemRecord({
      ...previous,
      ...details,
      sealedValue: sealVaultValue(rawValue, id),
      valueStored: true,
      valueFingerprint: sha256(rawValue),
      rotationStatus: details.rotationDays > 0 ? "planned" : "not-set",
      createdAt: previous.createdAt || now,
      updatedAt: now,
    }, { includeSealed: true });
    state.items[id] = item;
    writeVaultState(state);
    upsertVaultMaterialMetadata(item);
    appendAudit({ action: "vault.item.create.apply", target: `${projectId}/${targetEnv}/${itemKey}`, environment: targetEnv, risk: "high", result: "success", dryRun: false, summary: "Vault item stored encrypted; plaintext value was not logged or returned." });
    const publicItem = vaultItemRecord(item);
    const operation = operationPlan("vault.item.create.local", targetEnv, false, ["validate vault metadata", "encrypt value with local vault key", "write encrypted vault state", "update sensitive-material metadata", "write audit event"], { ...publicItem, valueStored: true, valueExposed: false, productionEvidence: false });
    return { ...operation, item: publicItem };
  }
  appendAudit({ action: "vault.item.create.plan", target: `${projectId}/${targetEnv}/${itemKey}`, environment: targetEnv, risk: "medium", result: "planned", dryRun: true, summary: "Vault item create plan generated; plaintext value was not stored." });
  return operationPlan("vault.item.create", targetEnv, true, ["validate vault metadata", "prepare encrypted local state", "require apply confirmation", "write audit event"], { ...details, valueProvided: Boolean(rawValue), valueStored: false, valueExposed: false, productionEvidence: false, confirmationRequired: "STORE-VAULT-SECRET" });
}

function planVaultSecretImportExisting(payload, context) {
  const state = readVaultState();
  const candidates = readExistingSecretCandidates();
  const replaceExisting = parseBoolean(payload.replaceExisting || "");
  const importable = candidates.filter((candidate) => replaceExisting || !state.items[candidate.id] || state.items[candidate.id]?.deletedAt);
  if (payload.confirm === "IMPORT-EXISTING-SECRETS") {
    const now = new Date().toISOString();
    const imported = [];
    const skipped = [];
    for (const candidate of candidates) {
      const previous = state.items[candidate.id] || {};
      if (!replaceExisting && state.items[candidate.id] && !state.items[candidate.id]?.deletedAt) {
        skipped.push(candidate.id);
        continue;
      }
      let rawValue = "";
      try {
        rawValue = readExistingSecretValue(candidate.filePath);
      } catch {
        skipped.push(candidate.id);
        continue;
      }
      if (!rawValue) {
        skipped.push(candidate.id);
        continue;
      }
      const item = vaultItemRecord({
        ...previous,
        id: candidate.id,
        itemKey: candidate.itemKey,
        label: candidate.label,
        projectId: "platform",
        environment: "local",
        kind: candidate.kind,
        username: "",
        url: candidate.sourceLabel,
        rotationDays: candidate.rotationDays,
        rotationStatus: candidate.rotationDays > 0 ? "planned" : "not-set",
        valueStored: true,
        valueFingerprint: sha256(rawValue),
        sealedValue: sealVaultValue(rawValue, candidate.id),
        source: candidate.source,
        createdAt: previous.createdAt || now,
        updatedAt: now,
      }, { includeSealed: true });
      state.items[item.id] = item;
      imported.push(vaultItemRecord(item));
    }
    writeVaultState(state);
    for (const item of imported) upsertVaultMaterialMetadata(item);
    appendAudit({ action: "vault.import-existing.apply", target: "platform/local", environment: "local", risk: "high", result: "success", dryRun: false, summary: `Imported ${imported.length} existing files into the encrypted Vault; values were not logged.` });
    const operation = operationPlan("vault.import-existing.local", "local", false, ["scan approved secret directories", "read existing values locally", "encrypt each value into the Vault", "preserve original files", "write audit event"], { itemCount: candidates.length, importedCount: imported.length, skippedCount: skipped.length, importedIds: imported.map((item) => item.id), valueExposed: false, productionEvidence: false });
    return { ...operation, items: imported };
  }
  appendAudit({ action: "vault.import-existing.plan", target: "platform/local", environment: "local", risk: "medium", result: "planned", dryRun: true, summary: "Existing secret import plan generated; values were not read." });
  return operationPlan("vault.import-existing", "local", true, ["scan approved secret directories", "show importable count", "require apply confirmation", "do not read values during plan"], { itemCount: candidates.length, importableCount: importable.length, valueRead: false, valueExposed: false, productionEvidence: false, confirmationRequired: "IMPORT-EXISTING-SECRETS" });
}

function planVaultSecretReveal(id, payload, context) {
  const itemId = sanitizeIdentifier(id || "");
  if (!itemId) throw new ValidationError("Vault item id is required.");
  const state = readVaultState();
  const existing = state.items[itemId];
  if (!existing || existing.deletedAt) throw new ValidationError("Vault item not found.");
  const item = vaultItemRecord(existing);
  if (!existing.sealedValue) throw new ValidationError("Vault item has no encrypted value.");
  const confirmation = `REVEAL-VAULT-SECRET:${item.id}`;
  if (payload.confirm !== confirmation) {
    appendAudit({ action: "vault.item.reveal.plan", target: item.id, environment: item.environment, risk: "high", result: "planned", dryRun: true, summary: "Vault item reveal plan generated; value was not read." });
    return operationPlan("vault.item.reveal", item.environment, true, ["validate vault item", "require reveal confirmation", "do not include value in normal inventory"], { itemId: item.id, projectId: item.projectId, valueRead: false, valueExposed: false, productionEvidence: false, confirmationRequired: confirmation });
  }
  const value = openVaultValue(existing.sealedValue, item.id);
  const now = new Date();
  const revealExpiresAt = new Date(now.getTime() + vaultRevealTtlMs).toISOString();
  appendAudit({ action: "vault.item.reveal.apply", target: item.id, environment: item.environment, risk: "high", result: "success", dryRun: false, summary: "Vault item value revealed to the local browser after explicit confirmation; value was not logged." });
  const operation = operationPlan("vault.item.reveal.local", item.environment, false, ["validate vault item", "decrypt in memory", "return value only for explicit browser action", "write audit event"], { itemId: item.id, projectId: item.projectId, valueRead: true, valueExposed: true, revealExpiresAt, productionEvidence: false });
  return { ...operation, item, value, revealExpiresAt, ttlMs: vaultRevealTtlMs };
}

function planVaultSecretDelete(id, payload, context) {
  const itemId = sanitizeIdentifier(id || "");
  if (!itemId) throw new ValidationError("Vault item id is required.");
  const state = readVaultState();
  const existing = state.items[itemId];
  if (!existing || existing.deletedAt) throw new ValidationError("Vault item not found.");
  const item = vaultItemRecord(existing);
  const confirmation = `DELETE-VAULT-SECRET:${item.id}`;
  if (payload.confirm === confirmation) {
    delete state.items[item.id];
    writeVaultState(state);
    removeVaultMaterialMetadata(item);
    appendAudit({ action: "vault.item.delete.apply", target: item.id, environment: item.environment, risk: "high", result: "success", dryRun: false, summary: "Vault item removed from encrypted state; value was not read or exposed." });
    const operation = operationPlan("vault.item.delete.local", item.environment, false, ["validate vault item", "remove encrypted vault record", "remove vault-owned material metadata", "write audit event"], { itemId: item.id, projectId: item.projectId, valueRemoved: true, valueRead: false, valueExposed: false, productionEvidence: false });
    return { ...operation, item: { ...item, deleted: true } };
  }
  appendAudit({ action: "vault.item.delete.plan", target: item.id, environment: item.environment, risk: "high", result: "planned", dryRun: true, summary: "Vault item delete plan generated; encrypted value was not read." });
  return operationPlan("vault.item.delete", item.environment, true, ["validate vault item", "require delete confirmation", "do not read value", "write audit event"], { itemId: item.id, projectId: item.projectId, valueRead: false, valueExposed: false, productionEvidence: false, confirmationRequired: confirmation });
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
  const workerId = sanitizeIdentifier(payload.workerId || "enterprise-backup-scheduler");
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
  const workerId = sanitizeIdentifier(payload.workerId || "enterprise-backup-scheduler");
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

function applyBackupFileDelete(payload, context) {
  const confirm = String(payload.confirm || "").trim();
  if (confirm !== "ELIMINA-BACKUP-FILE") {
    throw new RejectedOperationError("Conferma richiesta: scrivi ELIMINA-BACKUP-FILE.");
  }
  const relativePath = safeRelativeBackupPath(payload.path || payload.filePath || "");
  if (!relativePath) throw new ValidationError("Percorso backup richiesto.");
  if (!backupFileDeleteAllowed(relativePath)) {
    throw new RejectedOperationError("Questo tipo di file backup non puo' essere eliminato dal Control Center.");
  }
  const root = backupRealpath(path.resolve(backupRoot));
  const target = path.resolve(root, relativePath);
  if (!(target === root || target.startsWith(`${root}${path.sep}`))) {
    throw new ValidationError("Percorso backup non valido.");
  }
  if (!existsSync(target)) throw new ValidationError("File backup non trovato.");
  assertNoBackupPathSymlink(root, relativePath);
  const stat = lstatSync(target);
  if (stat.isDirectory() || stat.isSymbolicLink()) {
    throw new RejectedOperationError("Dal Control Center si eliminano solo file backup, non directory o symlink.");
  }
  const deletedFile = backupFileEntryRecord(target, path.basename(target), relativePath);
  rmSync(target, { force: false });
  appendAudit({ action: "backup.file.delete", target: relativePath, environment: context.environment, risk: "high", result: "success", dryRun: false, summary: "Backup file removed from local backup root after explicit confirmation." });
  const operation = operationPlan("backup.file.delete", context.environment, false, ["validate backup root", "validate file allowlist", "delete selected file", "write audit event"], {
    backupPath: relativePath,
    fileDeleted: true,
    sizeBytes: deletedFile?.sizeBytes || 0,
    productionEvidence: false,
  });
  const backup = backupRecord({
    operationId: operation.id,
    action: "delete-file",
    scope: relativePath,
    environment: context.environment,
    status: "deleted",
    dryRun: false,
    resultSummary: "Backup file deleted after explicit confirmation.",
  });
  appendBackupRecord(backup);
  return { ...operation, backup, deletedFile };
}

function operationPlan(type, targetEnv, dryRun, steps, details = {}) {
  const now = new Date().toISOString();
  const operationId = rid();
  const cleanDetails = sanitizeOperationDetails(details);
  const identity = requestIdentity.getStore();
  const operation = sanitizeEvent({
    id: operationId,
    operationId,
    type,
    status: dryRun ? "planned" : "accepted",
    projectId: cleanDetails.projectId || cleanDetails.project || cleanDetails.applicationId || cleanDetails.webspaceId || cleanDetails.subdomainId || "",
    environment: targetEnv,
    requestedBy: identity?.subject || "control-center",
    requestedByRole: identity?.role || "system",
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
  const parsed = controlState.read("projects", { strict: true }).value;
  return {
    ...parsed,
    projects: typeof parsed.projects === "object" && parsed.projects ? parsed.projects : {},
    subdomains: typeof parsed.subdomains === "object" && parsed.subdomains ? parsed.subdomains : {},
  };
}

function writeState(state) {
  controlState.write("projects", state);
}

function appendAudit(event) {
  const identity = requestIdentity.getStore();
  const record = sanitizeEvent({
    id: rid(),
    timestamp: new Date().toISOString(),
    actor: identity?.subject || "control-center",
    actorRole: identity?.role || "system",
    requestId: identity?.requestId || rid(),
    ...event,
  });
  controlState.append("audit", record);
}

function readAudit() {
  return recentStateEvents("audit", 100);
}

function appendOperation(operation) {
  controlState.append("operations", sanitizeEvent(operation));
}

function readOperations() {
  return recentStateEvents("operations", 100);
}

function appendStatusRun(run) {
  controlState.append("statusRuns", sanitizeEvent(run));
}

function readStatusRuns(limit = 20) {
  return recentStateEvents("statusRuns", limit);
}

function readLatestStatusRun() {
  return readStatusRuns(1)[0] || null;
}

function appendStatusRunEvent(event) {
  const record = sanitizeEvent(event);
  controlState.appendRetained("statusRunEvents", record, {
    maxRecords: statusEventRetentionMaxRecords,
    maxBytes: statusEventRetentionMaxBytes,
    maxRecordBytes: statusEventRetentionMaxRecordBytes,
  });
  statusEventBroker.publish(record);
}

function readStatusRunEvents(limit = 200, runId = "") {
  return readStatusRunEventPage(limit, runId).events;
}

function readStatusRunEventPage(limit = 200, runId = "") {
  const requestedLimit = clampNumber(Number(limit), 1, 2000);
  const tail = controlState.readTail("statusRunEvents", {
    strict: true,
    maxRecords: statusEventTailMaxRecords,
    maxBytes: statusEventTailMaxBytes,
    maxRecordBytes: statusEventMaxRecordBytes,
  });
  const filtered = runId ? tail.value.filter((event) => event.runId === runId) : tail.value;
  const events = filtered.slice(-requestedLimit);
  const missingRunPrefix = Boolean(runId && events.length > 0 && Number(events[0].sequence || 0) > 1);
  const sourceTruncated = runId
    ? missingRunPrefix || (tail.truncated && events.length === 0)
    : tail.truncated;
  return {
    events,
    truncated: sourceTruncated || filtered.length > events.length,
    sourceTruncated: tail.truncated,
    bytesRead: tail.bytesRead,
    parsedRecords: tail.parsedRecords,
  };
}

async function streamStatusRunEvents(req, res, requestedRunId) {
  if (!String(requestedRunId || "").trim()) throw new ValidationError("Status run ID is required.");
  const runId = normalizeStatusRunId(requestedRunId, 0);
  const afterSequence = statusStreamLastEventId(req);
  const principal = requestIdentity.getStore()?.subject || "";
  const subscription = statusEventBroker.subscribe({ principal, runId, afterSequence });
  const controller = new AbortController();
  const disconnect = () => {
    controller.abort();
    subscription.close("client-disconnect");
  };
  req.once("aborted", disconnect);
  res.once("close", disconnect);
  res.once("error", disconnect);
  try {
    const replay = readStatusRunEventPage(2000, runId);
    const replayEvents = replay.events.filter((event) => Number(event.sequence || 0) > afterSequence);
    if (subscription.closed) throw subscription.closeError || new StatusEventStreamError("Status stream closed before start.");
    const replayState = validateStatusEventReplay(replay.events, replayEvents, afterSequence);
    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive",
      "x-accel-buffering": "no",
      "x-platform-control-center-runtime": "node",
    });
    res.flushHeaders?.();
    if (replayState.completedAtCursor) {
      res.end();
      return;
    }
    await pumpStatusEventStream({
      response: res,
      subscription,
      replayEvents,
      afterSequence,
      heartbeatMs: statusStreamHeartbeatMs,
      maxDurationMs: statusStreamMaxDurationMs,
      backpressureTimeoutMs: statusStreamBackpressureTimeoutMs,
      signal: controller.signal,
    });
    if (!res.writableEnded && !res.destroyed) res.end();
  } catch (error) {
    if (!res.headersSent) throw error;
    if (!res.destroyed) res.destroy();
  } finally {
    req.removeListener("aborted", disconnect);
    res.removeListener("close", disconnect);
    res.removeListener("error", disconnect);
    controller.abort();
    subscription.close("stream-finished");
  }
}

function validateStatusEventReplay(retainedEvents, replayEvents, afterSequence) {
  if (afterSequence > 0 && !retainedEvents.some((event) => Number(event.sequence || 0) === afterSequence)) {
    throw new StatusEventStreamError("Status stream replay cursor is no longer retained.", "STATUS_STREAM_REPLAY_GAP", 409);
  }
  let cursor = afterSequence;
  for (const event of replayEvents) {
    const sequence = Number(event.sequence || 0);
    if (!Number.isSafeInteger(sequence) || sequence !== cursor + 1) {
      throw new StatusEventStreamError("Status stream replay contains a sequence gap.", "STATUS_STREAM_REPLAY_GAP", 409);
    }
    cursor = sequence;
  }
  return {
    completedAtCursor: retainedEvents.some((event) => event.type === "run-completed" && Number(event.sequence || 0) <= afterSequence),
  };
}

function statusStreamLastEventId(req) {
  const header = Array.isArray(req.headers["last-event-id"])
    ? req.headers["last-event-id"][0]
    : req.headers["last-event-id"];
  const value = String(header || "").trim();
  if (!value) return 0;
  if (!/^\d{1,16}$/.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new ValidationError("Last-Event-ID must be a non-negative safe integer.");
  }
  return Number(value);
}

function objectState(name) {
  const parsed = controlState.read(name, { strict: true }).value;
  validateStateRecord(parsed);
  return parsed;
}

function recentStateEvents(name, limit = 100) {
  const records = controlState.read(name, { strict: true }).value;
  return records.slice(-Math.max(0, limit)).reverse();
}

function readApplicationsState() {
  return objectState("applications");
}

function writeApplicationsState(state) {
  controlState.write("applications", sanitizeEvent(state));
}

function readDomainsState() {
  return objectState("domains");
}

function writeDomainsState(state) {
  controlState.write("domains", sanitizeEvent(state));
}

function readWebspacesState() {
  return objectState("webspaces");
}

function writeWebspacesState(state) {
  controlState.write("webspaces", sanitizeEvent(state));
}

function readDatabasesState() {
  if (!existsSync(databasesFile)) return {};
  try {
    const parsed = JSON.parse(readFileSync(databasesFile, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid database state");
    return parsed;
  } catch {
    throw new ValidationError("Database state is unreadable; no write was performed.");
  }
}

function writeDatabasesState(state) {
  writePrivateJsonAtomic(databasesFile, sanitizeEvent(state));
}

function readDatabaseDeleteOperationsState() {
  if (!existsSync(databaseDeleteOperationsFile)) return { version: 1, operations: {}, updatedAt: null };
  try {
    const parsed = JSON.parse(readFileSync(databaseDeleteOperationsFile, "utf8"));
    if (parsed?.version !== 1 || !parsed.operations || typeof parsed.operations !== "object" || Array.isArray(parsed.operations)) throw new Error("invalid delete operation state");
    for (const operation of Object.values(parsed.operations)) parseDatabaseDeleteOperation(operation);
    return parsed;
  } catch {
    throw new ValidationError("Database destructive operation state is unreadable; no database mutation was performed.");
  }
}

function writeDatabaseDeleteOperationsState(state) {
  const operations = Object.fromEntries(Object.entries(state.operations || {}).map(([id, operation]) => [sanitizeIdentifier(id), parseDatabaseDeleteOperation(operation)]));
  writePrivateJsonAtomic(databaseDeleteOperationsFile, { version: 1, operations, updatedAt: new Date().toISOString() });
}

function readDatabasePrincipalsState() {
  if (!existsSync(databasePrincipalsFile)) return { version: 1, bindings: {}, updatedAt: null };
  try {
    const parsed = JSON.parse(readFileSync(databasePrincipalsFile, "utf8"));
    if (!parsed || parsed.version !== 1 || !parsed.bindings || typeof parsed.bindings !== "object" || Array.isArray(parsed.bindings)) {
      throw new Error("invalid database principal registry");
    }
    return parsed;
  } catch {
    throw new ValidationError("Database principal registry is unreadable; no database mutation was performed.");
  }
}

function writeDatabasePrincipalsState(state) {
  writePrivateJsonAtomic(databasePrincipalsFile, {
    version: 1,
    updatedAt: new Date().toISOString(),
    bindings: sanitizeEvent(state.bindings || {}),
  });
}

function writePrivateJsonAtomic(filePath, value) {
  mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  let fd = null;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(temporary, filePath);
  } catch (error) {
    if (fd !== null) closeSync(fd);
    rmSync(temporary, { force: true });
    throw error;
  }
}

function readStorageBucketsState() {
  return objectState("storageBuckets");
}

function writeStorageBucketsState(state) {
  controlState.write("storageBuckets", sanitizeEvent(state));
}

function readSensitiveMaterialsState() {
  return objectState("sensitiveMaterials");
}

function writeSensitiveMaterialsState(state) {
  controlState.write("sensitiveMaterials", sanitizeEvent(state));
}

function readVaultState() {
  if (!existsSync(vaultFile)) return { version: 2, items: {}, updatedAt: null };
  try {
    const parsed = JSON.parse(readFileSync(vaultFile, "utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !parsed.items || typeof parsed.items !== "object" || Array.isArray(parsed.items)) {
      throw new Error("invalid Vault state shape");
    }
    return {
      version: Number(parsed?.version) === 2 ? 2 : 1,
      items: parsed.items,
      updatedAt: parsed?.updatedAt || null,
    };
  } catch {
    throw new ValidationError("Vault state is unreadable; no write was performed.");
  }
}

function writeVaultState(state) {
  const now = new Date().toISOString();
  const normalized = {
    version: 2,
    updatedAt: now,
    items: Object.fromEntries(
      Object.values(state.items || {})
        .filter((item) => item && !item.deletedAt)
        .map((item) => {
          const record = vaultItemRecord(item, { includeSealed: true });
          return [record.id, record];
        }),
    ),
  };
  mkdirSync(path.dirname(vaultFile), { recursive: true });
  const temporary = `${vaultFile}.tmp-${process.pid}-${randomBytes(6).toString("hex")}`;
  let fd = null;
  try {
    fd = openSync(temporary, "wx", 0o600);
    writeFileSync(fd, `${JSON.stringify(normalized, null, 2)}\n`, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = null;
    renameSync(temporary, vaultFile);
  } catch (error) {
    if (fd !== null) closeSync(fd);
    rmSync(temporary, { force: true });
    throw error;
  }
}

function readExistingSecretCandidates() {
  const roots = [
    { root: existingSecretsDir, origin: "repo-secrets" },
    ...(includeRunSecretsInVaultImport ? [{ root: "/run/secrets", origin: "docker-secrets" }] : []),
    { root: databaseCredentialDir, origin: "database-credentials" },
  ];
  const candidates = [];
  const seen = new Set();
  for (const entry of roots) {
    for (const file of listExistingSecretFiles(entry.root, entry.origin)) {
      const itemKey = existingSecretItemKey(file.relativePath);
      const id = vaultItemId("platform", "local", itemKey);
      if (seen.has(id)) continue;
      seen.add(id);
      candidates.push({
        id,
        itemKey,
        label: humanName(itemKey),
        kind: existingSecretKind(itemKey, file.relativePath),
        rotationDays: existingSecretRotationDays(itemKey),
        source: `existing-${file.origin}:${file.relativePath}`,
        sourceLabel: `${file.origin}/${file.relativePath}`,
        filePath: file.filePath,
        sizeBytes: file.sizeBytes,
      });
    }
  }
  return candidates.sort((a, b) => a.itemKey.localeCompare(b.itemKey));
}

function summarizeExistingSecretImport(candidates, vaultItems) {
  const present = new Set((vaultItems || []).map((item) => item.id));
  const importable = (candidates || []).filter((candidate) => !present.has(candidate.id));
  return {
    candidateCount: candidates.length,
    importableCount: importable.length,
  };
}

function listExistingSecretFiles(root, origin) {
  const files = [];
  if (!root) return files;
  let rootReal = "";
  try {
    if (!safeIsDirectory(root)) return files;
    rootReal = realpathSync(root);
  } catch {
    return files;
  }
  const visit = (current, depth = 0) => {
    if (depth > 3) return;
    let entries = [];
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const filePath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith(".") || ["node_modules", ".git"].includes(entry.name)) continue;
        visit(filePath, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      const candidate = existingSecretFileRecord(rootReal, filePath, origin);
      if (candidate) files.push(candidate);
    }
  };
  visit(rootReal);
  return files;
}

function existingSecretFileRecord(rootReal, filePath, origin) {
  try {
    const fileReal = realpathSync(filePath);
    if (!(fileReal === rootReal || fileReal.startsWith(`${rootReal}${path.sep}`))) return null;
    const stat = statSync(fileReal);
    if (!stat.isFile() || stat.size <= 0 || stat.size > 1024 * 1024) return null;
    const relativePath = path.relative(rootReal, fileReal).replaceAll(path.sep, "/");
    if (shouldSkipExistingSecretFile(relativePath)) return null;
    return { filePath: fileReal, relativePath, origin, sizeBytes: stat.size };
  } catch {
    return null;
  }
}

function shouldSkipExistingSecretFile(relativePath) {
  const name = path.basename(relativePath).toLowerCase();
  if (!name || name.startsWith(".")) return true;
  if (["readme.md", "infra-secret-manager-audit.log", "infra-secret-manager-store.json", "secret-vault.json"].includes(name)) return true;
  if (name.endsWith(".sha256") || name.endsWith(".sig") || name.endsWith(".md") || name.endsWith(".log")) return true;
  return false;
}

function existingSecretItemKey(relativePath) {
  let key = String(relativePath || "")
    .replace(/\\/g, "/")
    .replace(/\.txt$/i, "")
    .replace(/\.conf$/i, "_conf")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_")
    .slice(0, 120);
  if (!/^[a-z]/.test(key)) key = `secret_${key}`;
  return validateVaultItemKey(key || "secret_value");
}

function existingSecretKind(itemKey, relativePath) {
  const text = `${itemKey} ${relativePath}`.toLowerCase();
  if (/(github|cloudflare|smtp|alertmanager|webhook|turnstile)/.test(text)) return "provider";
  if (/(rclone|restic|minio|backup)/.test(text)) return "storage";
  if (/(database|mariadb|postgres|redis|nats|keycloak|phpmyadmin|pgadmin|db)/.test(text)) return "database";
  if (/(key|signing|session|pepper|master|hash)/.test(text)) return "kms";
  return "application";
}

function existingSecretRotationDays(itemKey) {
  const text = String(itemKey || "").toLowerCase();
  if (/(signing|session|pepper|master|key)/.test(text)) return 180;
  return 90;
}

function readExistingSecretValue(filePath) {
  return readFileSync(filePath, "utf8").replace(/\r?\n$/, "");
}

function readWorkerJobsState() {
  const parsed = objectState("workerJobs");
  return {
    workers: parsed && typeof parsed.workers === "object" && !Array.isArray(parsed.workers) ? parsed.workers : {},
    queues: parsed && typeof parsed.queues === "object" && !Array.isArray(parsed.queues) ? parsed.queues : {},
    jobs: parsed && typeof parsed.jobs === "object" && !Array.isArray(parsed.jobs) ? parsed.jobs : {},
    schedules: parsed && typeof parsed.schedules === "object" && !Array.isArray(parsed.schedules) ? parsed.schedules : {},
  };
}

function writeWorkerJobsState(state) {
  controlState.write("workerJobs", sanitizeEvent({
    workers: state.workers || {},
    queues: state.queues || {},
    jobs: state.jobs || {},
    schedules: state.schedules || {},
  }));
}

function readIdentityAccessState() {
  const parsed = objectState("identityAccess");
  return {
    users: parsed && typeof parsed.users === "object" && !Array.isArray(parsed.users) ? parsed.users : {},
    teams: parsed && typeof parsed.teams === "object" && !Array.isArray(parsed.teams) ? parsed.teams : {},
    roles: parsed && typeof parsed.roles === "object" && !Array.isArray(parsed.roles) ? parsed.roles : {},
    sessions: parsed && typeof parsed.sessions === "object" && !Array.isArray(parsed.sessions) ? parsed.sessions : {},
    accessReviews: parsed && typeof parsed.accessReviews === "object" && !Array.isArray(parsed.accessReviews) ? parsed.accessReviews : {},
  };
}

function writeIdentityAccessState(state) {
  controlState.write("identityAccess", sanitizeEvent({
    users: state.users || {},
    teams: state.teams || {},
    roles: state.roles || {},
    sessions: state.sessions || {},
    accessReviews: state.accessReviews || {},
  }));
}

function readResourceLimitsState() {
  return objectState("resourceLimits");
}

function writeResourceLimitsState(state) {
  controlState.write("resourceLimits", sanitizeEvent(state));
}

function readSecurityPoliciesState() {
  return objectState("securityPolicies");
}

function writeSecurityPoliciesState(state) {
  controlState.write("securityPolicies", sanitizeEvent(state));
}

function readAlertsState() {
  return objectState("alerts");
}

function writeAlertsState(state) {
  controlState.write("alerts", sanitizeEvent(state));
}

function readNotificationChannelsState() {
  return objectState("notificationChannels");
}

function writeNotificationChannelsState(state) {
  controlState.write("notificationChannels", sanitizeEvent(state));
}

function readProviderConnectionsState() {
  return objectState("providerConnections");
}

function writeProviderConnectionsState(state) {
  controlState.write("providerConnections", sanitizeEvent(state));
}

function readSettingsState() {
  return objectState("settings");
}

function writeSettingsState(state) {
  controlState.write("settings", sanitizeEvent(state));
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
  controlState.append("deployments", sanitizeEvent(deployment));
}

function readDeployments() {
  return recentStateEvents("deployments", 100);
}

function backupRecord({ operationId, jobId = "", action, scope, environment: targetEnv, status, dryRun, backupRef = "", resultSummary }) {
  return sanitizeEvent({
    id: rid(),
    operationId,
    jobId,
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
  controlState.append("backupRecords", sanitizeEvent(record));
}

function readBackupRecords() {
  return recentStateEvents("backupRecords", 100);
}

async function readPayload(req) {
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
      return req.controlCenterPayload;
    } catch {
      throw new ValidationError("Invalid JSON payload.");
    }
  }
  const params = new URLSearchParams(raw);
  req.controlCenterPayload = Object.fromEntries(params.entries());
  return req.controlCenterPayload;
}

function sealVaultValue(value, itemId) {
  try {
    return sealVaultPlaintext(value, itemId, loadVaultKeyring({ keyFile: vaultKeyFile, activeKeyId: vaultActiveKeyId }));
  } catch {
    throw new ValidationError("Dedicated Vault keyring is not configured or valid.");
  }
}

function openVaultValue(sealedValue, itemId) {
  const sealed = normalizeSealedValue(sealedValue);
  if (!sealed || sealed.alg !== "aes-256-gcm" || !sealed.iv || !sealed.tag || !sealed.data) {
    throw new ValidationError("Vault value is not readable.");
  }
  try {
    if (sealed.version === 2) {
      return openVaultCiphertext(sealed, itemId, loadVaultKeyring({ keyFile: vaultKeyFile, activeKeyId: vaultActiveKeyId }));
    }
    return openLegacyVaultCiphertext(sealed, itemId, readLegacyVaultMaterial(vaultLegacyKeyFile));
  } catch {
    throw new ValidationError("Vault value cannot be authenticated with an available Vault key.");
  }
}

function wantsJson(req) {
  return String(req.headers.accept || "").includes("application/json") || String(req.headers["content-type"] || "").includes("application/json");
}

function sha256(value) {
  return createHash("sha256").update(String(value)).digest("hex");
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

function validateVaultItemKey(value) {
  const name = String(value || "").trim().toLowerCase().replace(/\s+/g, "_");
  if (!/^[a-z][a-z0-9_.-]{1,127}$/.test(name)) throw new ValidationError("Invalid vault item name.");
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

function vaultItemId(projectId, targetEnv, itemKey) {
  return sanitizeIdentifier(`${projectId}-${targetEnv}-${itemKey.replace(/[_.]+/g, "-")}`);
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
  principalBindingId = "",
  principalManaged = false,
  principalBindingStatus = "legacy-unbound",
  status = "declared",
  connectionStatus = "metadata-only",
  sizeBytes = 0,
  slowQueries = "planned-adapter",
  users = [],
  permissions = [],
  linkedApps = [],
  credentialRef = "",
  credentialFile = "",
  credentialStatus = "protected",
  credentialUpdatedAt = null,
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
    principalBindingId: sanitizeIdentifier(principalBindingId),
    principalManaged: Boolean(principalManaged),
    principalBindingStatus: choice(String(principalBindingStatus || "legacy-unbound"), ["legacy-unbound", "reserved", "active", "migration-required", "retired"], "database principal binding status"),
    environment: "local",
    status,
    connectionStatus,
    sizeBytes: Number.isSafeInteger(Number(sizeBytes)) && Number(sizeBytes) >= 0 ? Number(sizeBytes) : 0,
    slowQueries,
    users: Array.isArray(users) ? users.map((user) => sanitizeOptionalRef(user)).filter(Boolean).slice(0, 20) : [],
    permissions: Array.isArray(permissions) ? permissions.map((permission) => sanitizeOptionalRef(permission)).filter(Boolean).slice(0, 20) : [],
    linkedApps: Array.isArray(linkedApps) ? [...new Set(linkedApps.map((item) => sanitizeIdentifier(item)).filter(Boolean))].slice(0, 20) : [],
    credentialRef: sanitizeOptionalRef(credentialRef),
    credentialFile: sanitizeCredentialFilePath(credentialFile),
    credentialStatus: choice(String(credentialStatus || "protected"), ["protected", "secret-ref-set", "secret-file-set", "rotation-requested", "rotation-requested-secret-ref", "missing"], "database credential status"),
    credentialUpdatedAt,
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

function vaultItemRecord({
  id = "",
  itemKey = "",
  label = "",
  projectId = "platform",
  environment: targetEnv = "local",
  kind = "application",
  username = "",
  url = "",
  rotationDays = 90,
  rotationStatus = "",
  valueStored = false,
  valueFingerprint = "",
  sealedValue = null,
  source = "control-center-vault",
  createdAt = null,
  updatedAt = null,
  deletedAt = null,
} = {}, { includeSealed = false } = {}) {
  const cleanProjectId = sanitizeIdentifier(projectId || "platform") || "platform";
  const cleanEnv = normalizeEnvironment(targetEnv);
  const cleanKey = validateVaultItemKey(itemKey || "secret_value");
  const cleanRotationDays = parseRotationDays(rotationDays || 0);
  const cleanFingerprint = sanitizeVaultFingerprint(valueFingerprint);
  const clean = sanitizeEvent({
    id: sanitizeIdentifier(id || vaultItemId(cleanProjectId, cleanEnv, cleanKey)),
    itemKey: cleanKey,
    label: sanitizeVaultText(label || humanName(cleanKey), 96),
    projectId: cleanProjectId,
    environment: cleanEnv,
    kind: choice(String(kind || "application"), ["application", "docker", "provider", "kms", "database", "storage"], "vault item kind"),
    username: sanitizeVaultText(username, 120),
    url: sanitizeVaultText(url, 200),
    rotationDays: cleanRotationDays,
    rotationStatus: rotationStatus || (cleanRotationDays > 0 ? "planned" : "not-set"),
    valueStored: Boolean(valueStored || sealedValue),
    fingerprintStored: Boolean(cleanFingerprint),
    valueFingerprint: includeSealed ? cleanFingerprint : "",
    valueExposed: false,
    source: sanitizeOptionalRef(source || "control-center-vault"),
    createdAt,
    updatedAt,
    deletedAt,
  });
  if (includeSealed) clean.sealedValue = normalizeSealedValue(sealedValue);
  return clean;
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
  workerId = "enterprise-backup-scheduler",
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
  const cleanWorkerId = sanitizeIdentifier(workerId || "enterprise-backup-scheduler") || "enterprise-backup-scheduler";
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
  workerId = "enterprise-backup-scheduler",
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
    workerId: sanitizeIdentifier(workerId || "enterprise-backup-scheduler") || "enterprise-backup-scheduler",
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
      mfaStatus: controlAuth.enabled ? "passkey-required" : "test-only-disabled",
      passkeyStatus: security.passkeyAdminAuth,
      vpnStatus: security.adminProtection === "vpn-required" ? "required" : "metadata-only",
      status: controlAuth.enabled ? "configured" : "local-dev",
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
      status: "configured",
      sessionSecretConfigured: false,
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
    loginAudit: audit.filter((event) => /^admin\.(?:oidc\.)?login\./.test(String(event.action || ""))).slice(0, 12),
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
    monitoringSignalRecord("workload-container-metrics", "Docker workload metrics", "node-exporter-textfile", hasJob("node-exporter") && hasPanel(/Workload CPU|Workload memory|effective limit/i) && hasAlert(/ContainerCpuUsageHigh|ContainerMemoryUsageHigh|ContainerDisappeared/i)),
    monitoringSignalRecord("node-exporter-host-metrics", "node-exporter host metrics", "node-exporter", hasJob("node-exporter") && hasAlert(/HostDiskUsageHigh|HostMemoryUsageHigh|HostCpuUsageHigh/i)),
    monitoringSignalRecord("platform-errors", "Platform errors", "loki", hasPanel(/Platform container logs|Platform errors|level=~\\"warn\|error\\"/i)),
    monitoringSignalRecord("alert-delivery", "Alert delivery", "prometheus", hasPanel(/Alert delivery|platform_alert_delivery_total/i) && hasAlert(/AlertDeliveryFailed/i)),
    monitoringSignalRecord("waf-events", "WAF events", "loki", hasPanel(/WAF events|ModSecurity/i)),
    monitoringSignalRecord("auth-failures", "Auth failures", "loki", hasPanel(/Auth failures|auth.*failed/i)),
    monitoringSignalRecord("latency", "Latency", "external-uptime", true),
    monitoringSignalRecord("error-rate", "Error rate", "prometheus-loki", hasPanel(/error logs|level=~\\"warn\|error\\"|HTTP request rate/i) || hasAlert(/PlatformTargetDown|ContainerDisappeared/i)),
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
  if (["prometheus", "alertmanager", "platform-alert-dispatcher", "traefik", "keycloak", "control-center", "project-router"].includes(jobName)) return "platform";
  if (/^workload-/.test(jobName)) return "hosted-workload";
  return "custom";
}

function monitoringPanelSignal(title, query) {
  const text = `${title}\n${query}`;
  if (/Platform container logs/i.test(text)) return "platform-errors";
  if (/Alert delivery outcomes|platform_alert_delivery_total/i.test(text)) return "alert-delivery";
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
  if (/Workload|Container/i.test(text)) return "hosted-workload";
  if (/Platform|Redis|Keycloak|Traefik|Alertmanager/i.test(text)) return "platform";
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
    { id: "control-center-session", name: "Control Center session store", status: controlAuth.enabled ? "PostgreSQL-backed" : "test-only disabled", materialConfigured: controlAuth.enabled, valueExposed: false, productionEvidence: false },
    { id: "admin-identity", name: "Admin identity provider", status: controlAuth.mode === "oidc-passkey" ? "OIDC passkey-only" : "test-only disabled", materialConfigured: controlAuth.mode === "oidc-passkey", valueExposed: false, productionEvidence: false },
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

function sanitizeVaultText(value, maxLength = 120) {
  return sanitizeMessage(String(value || "")).replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim().slice(0, maxLength);
}

function sanitizeVaultFingerprint(value) {
  const fingerprint = String(value || "").trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(fingerprint) ? fingerprint : "";
}

function normalizeSealedValue(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return {
    version: Number(value.version) === 2 ? 2 : 1,
    alg: sanitizeOptionalRef(value.alg || "aes-256-gcm"),
    keyId: sanitizeOptionalRef(value.keyId || ""),
    keyRef: sanitizeOptionalRef(value.keyRef || ""),
    iv: sanitizeSealedVaultChunk(value.iv, 64),
    tag: sanitizeSealedVaultChunk(value.tag, 128),
    data: sanitizeSealedVaultChunk(value.data, 2 * 1024 * 1024),
    createdAt: value.createdAt || null,
  };
}

function sanitizeSealedVaultChunk(value, maxLength) {
  const raw = String(value || "").trim();
  if (!raw || raw.length > maxLength || !/^[a-zA-Z0-9_-]+$/.test(raw)) return "";
  return raw;
}

function upsertVaultMaterialMetadata(item) {
  const materialName = vaultMaterialName(item.itemKey);
  const id = materialId(item.projectId || "platform", item.environment, materialName);
  const state = readSensitiveMaterialsState();
  state[id] = {
    ...(state[id] || {}),
    ...sensitiveMaterialRecord({
      id,
      projectId: item.projectId || "platform",
      environment: item.environment,
      materialName,
      materialKind: item.kind,
      materialConfigured: true,
      rotationDays: item.rotationDays,
      usageTargets: [item.projectId || "platform"],
      source: "control-center-vault",
      createdAt: state[id]?.createdAt || item.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }),
  };
  writeSensitiveMaterialsState(state);
}

function removeVaultMaterialMetadata(item) {
  const materialName = vaultMaterialName(item.itemKey);
  const id = materialId(item.projectId || "platform", item.environment, materialName);
  const state = readSensitiveMaterialsState();
  if (state[id]?.source === "control-center-vault") {
    delete state[id];
    writeSensitiveMaterialsState(state);
  }
}

function vaultMaterialName(itemKey) {
  let name = String(itemKey || "secret_value").toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  if (!/^[A-Z]/.test(name)) name = `SECRET_${name}`;
  if (name.length < 2) name = `${name}_VALUE`;
  return validateMaterialName(name.slice(0, 128));
}

function sanitizeCredentialFilePath(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const resolved = path.resolve(raw);
  const allowedRoots = ["/run/secrets", "/var/www/project-state", path.resolve(path.dirname(databasesFile))];
  return allowedRoots.some((root) => resolved === root || resolved.startsWith(`${root}${path.sep}`)) ? resolved : "";
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
      ["security", "Sicurezza", "SEC"], ["backups", "Backup", "BKP"], ["logs", "Log e alert", "LOG"],
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

function htmlPage(req, res, content, status = 200) {
  const etag = `"${createHash("sha256").update(content).digest("base64url")}"`;
  const headers = {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "private, max-age=0, must-revalidate",
    etag,
    "x-platform-control-center-runtime": "node",
  };
  if (status === 200 && String(req.headers["if-none-match"] || "") === etag) {
    res.writeHead(304, headers);
    res.end();
    return;
  }
  res.writeHead(status, headers);
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
  const content = readFileSync(target);
  const etag = `"${createHash("sha256").update(content).digest("base64url")}"`;
  const headers = {
    "content-type": contentTypes[extension] || "application/octet-stream",
    "cache-control": "public, max-age=3600, must-revalidate",
    etag,
    "x-platform-control-center-runtime": "node",
  };
  if (String(req.headers["if-none-match"] || "") === etag) {
    res.writeHead(304, headers);
    res.end();
    return;
  }
  res.writeHead(200, headers);
  res.end(content);
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
