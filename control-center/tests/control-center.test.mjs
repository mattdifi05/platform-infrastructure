import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { generatedDatabasePrincipal } from "../database/ownership.mjs";
import {
  backupDocumentDigest,
  backupResourceId,
  createBackupJobDocument,
  createBackupManifestDocument,
} from "../backup/contracts.mjs";

function fixtureCredential(...parts) {
  return parts.join("-");
}

const infraRoot = path.resolve(import.meta.dirname, "..", "..");
const testRoot = path.join(infraRoot, ".tmp", "control-center-tests", randomUUID());
const projectsRoot = path.join(testRoot, "projects");
const backupsRoot = path.join(testRoot, "backups");
const stateDir = path.join(testRoot, "state");
const stateFile = path.join(stateDir, "projects.json");
const auditFile = path.join(stateDir, "audit.jsonl");
const operationsFile = path.join(stateDir, "operations.jsonl");
const applicationsFile = path.join(stateDir, "applications.json");
const domainsFile = path.join(stateDir, "domains.json");
const databasesFile = path.join(stateDir, "databases.json");
const databasePrincipalsFile = path.join(stateDir, "database-principals.json");
const databaseDeleteOperationsFile = path.join(stateDir, "database-destructive-operations.json");
const storageBucketsFile = path.join(stateDir, "storage-buckets.json");
const sensitiveMaterialsFile = path.join(stateDir, "sensitive-materials.json");
const vaultFile = path.join(stateDir, "secret-vault.json");
const vaultKeyFile = path.join(stateDir, "vault.key");
const existingSecretsDir = path.join(testRoot, "existing-secrets");
const workerJobsFile = path.join(stateDir, "worker-jobs.json");
const identityAccessFile = path.join(stateDir, "identity-access.json");
const deploymentsFile = path.join(stateDir, "deployments.jsonl");
const backupRecordsFile = path.join(stateDir, "backups.jsonl");
const backupJobsDir = path.join(stateDir, "backup-jobs");
const resourceLimitsFile = path.join(stateDir, "resource-limits.json");
const securityPoliciesFile = path.join(stateDir, "security-policies.json");
const alertsFile = path.join(stateDir, "alerts.json");
const notificationChannelsFile = path.join(stateDir, "notification-channels.json");
const providerConnectionsFile = path.join(stateDir, "provider-connections.json");
const settingsFile = path.join(stateDir, "settings.json");
const webspacesFile = path.join(stateDir, "webspaces.json");
const dockerStatsFile = path.join(stateDir, "docker-stats.json");
const statusRunsFile = path.join(stateDir, "status-runs.jsonl");
const statusRunEventsFile = path.join(stateDir, "status-run-events.jsonl");
const reportsRoot = path.join(testRoot, "reports");
const longExistingVaultValue = `existing-long-provider-secret-${"x".repeat(260)}`;

test("Admin Control Center local foundation", async (t) => {
  prepareFixture();
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_ENV: "local",
      CONTROL_CENTER_AUTH_MODE: "test-disabled",
      CONTROL_CENTER_DATABASE_LIVE_APPLY: "false",
      CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "true",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      CONTROL_CENTER_BACKUP_ROOT: backupsRoot,
      PROJECTS_ROOT: projectsRoot,
      PROJECT_STATE_FILE: stateFile,
      PROJECT_AUDIT_FILE: auditFile,
      PROJECT_OPERATIONS_FILE: operationsFile,
      PROJECT_APPLICATIONS_FILE: applicationsFile,
      PROJECT_DOMAINS_FILE: domainsFile,
      PROJECT_DATABASES_FILE: databasesFile,
      PROJECT_DATABASE_PRINCIPALS_FILE: databasePrincipalsFile,
      PROJECT_DATABASE_DESTRUCTIVE_OPERATIONS_FILE: databaseDeleteOperationsFile,
      CONTROL_CENTER_REPORTS_ROOT: reportsRoot,
      PROJECT_STORAGE_BUCKETS_FILE: storageBucketsFile,
      PROJECT_SENSITIVE_MATERIALS_FILE: sensitiveMaterialsFile,
      PROJECT_VAULT_FILE: vaultFile,
      CONTROL_CENTER_VAULT_KEY_FILE: vaultKeyFile,
      CONTROL_CENTER_EXISTING_SECRETS_DIR: existingSecretsDir,
      PROJECT_WORKER_JOBS_FILE: workerJobsFile,
      PROJECT_IDENTITY_ACCESS_FILE: identityAccessFile,
      PROJECT_DEPLOYMENTS_FILE: deploymentsFile,
      PROJECT_BACKUP_RECORDS_FILE: backupRecordsFile,
      PROJECT_BACKUP_JOBS_DIR: backupJobsDir,
      PROJECT_RESOURCE_LIMITS_FILE: resourceLimitsFile,
      PROJECT_SECURITY_POLICIES_FILE: securityPoliciesFile,
      PROJECT_ALERTS_FILE: alertsFile,
      PROJECT_NOTIFICATION_CHANNELS_FILE: notificationChannelsFile,
      PROJECT_PROVIDER_CONNECTIONS_FILE: providerConnectionsFile,
      PROJECT_SETTINGS_FILE: settingsFile,
      PROJECT_WEBSPACES_FILE: webspacesFile,
      PROJECT_DOCKER_STATS_FILE: dockerStatsFile,
      CONTROL_CENTER_DOCKER_STATS_MAX_AGE_SECONDS: "120",
      PROJECT_STATUS_RUNS_FILE: statusRunsFile,
      PROJECT_STATUS_RUN_EVENTS_FILE: statusRunEventsFile,
      CONTROL_CENTER_STATUS_STEP_DELAY_MS: "0",
      CONTROL_CENTER_STATUS_PROBE_TIMEOUT_MS: "500",
      CONTROL_CENTER_HOST: "portal.localhost.com",
      DOCS_HOST: "docs.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
      NODE_PROJECT_HOSTS: "node-demo=node-demo.localhost.com",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  t.after(async () => {
    await stopChild(child);
    rmSync(testRoot, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHealth(`${baseUrl}/__health`, child);

  const health = await getJson(`${baseUrl}/__health`);
  assert.equal(health.service, "control-center");

  const html = await getText(`${baseUrl}/`);
  assert.match(html, /Admin Control Center/);
  assert.match(html, /<body data-cc-theme="light">/);
  assert.doesNotMatch(html, /data-cc-preloading|cc-preload-screen|Caricamento portale/);
  assert.match(html, /ops-shell/);
  assert.match(html, /Stato/);
  assert.match(html, /Applicazioni/);
  assert.doesNotMatch(html, /Attività/);
  assert.doesNotMatch(html, /section=activity/);
  assert.doesNotMatch(html, />Risorse<\/a>/);
  assert.doesNotMatch(html, /href="\/\?section=files"/);
  assert.doesNotMatch(html, /href="\/\?section=databases"/);
  assert.match(html, /NO GO LIVE/);
  assert.match(html, /Esecuzione/);
  assert.match(html, /data-status-run-form/);
  assert.match(html, /<details class="ops-status-runner" data-status-run-console>/);
  assert.doesNotMatch(html, /<details class="ops-status-runner"[^>]*open/);
  assert.doesNotMatch(html, /ops-status-section-list/);
  assert.match(html, /data-status-section-detail=/);
  assert.doesNotMatch(html, /data-status-tabs/);
  assert.doesNotMatch(html, /data-status-tab="all"/);
  assert.match(html, /data-ops-nav-group="status" data-ops-nav-expanded="true" data-ops-nav-has-active-child="true" data-ops-nav-locked="true"/);
  assert.match(html, /<span class="ops-nav-pill" aria-hidden="true"><\/span>/);
  assert.match(html, /id="ops-nav-panel-status" aria-hidden="false"/);
  assert.match(html, /data-ops-nav-toggle/);
  assert.match(html, /aria-label="Sezione attuale: Stato" aria-expanded="true" aria-controls="ops-nav-panel-status" aria-disabled="true"/);
  assert.match(html, /aria-label="Apri Applicazioni" aria-expanded="false" aria-controls="ops-nav-panel-projects"/);
  assert.match(html, /<button class="ops-nav-main" type="button" data-ops-nav-toggle aria-label="Sezione attuale: Stato"/);
  assert.doesNotMatch(html, /<a class="ops-nav-main/);
  assert.match(html, /data-ops-nav-group="projects" data-ops-nav-expanded="false" data-ops-nav-has-active-child="false" data-ops-nav-locked="false"/);
  assert.match(html, /id="ops-nav-panel-projects" aria-hidden="true"/);
  assert.doesNotMatch(html, /data-ops-nav-group="backups"/);
  assert.doesNotMatch(html, /ops-nav-panel-backups/);
  assert.match(html, /href="\/\?section=status&amp;statusCategory=domain-edge#status-run"/);
  assert.match(html, /class="ops-nav-subitem active [^"]*" aria-current="page" data-status-category-card="go-live"[^>]*href="\/\?section=status&amp;statusCategory=go-live#status-run"/);
  assert.match(html, /data-status-category-card="go-live"/);
  assert.match(html, /statusCategory=domain-edge/);
  assert.match(html, /Esegui sezione/);
  assert.match(html, /name="scope" value="category"/);
  assert.match(html, /name="scope" value="check"/);
  assert.match(html, /data-status-run-inline/);
  assert.match(html, /Avvia test reali/);
  assert.match(html, /action="\/actions\/status-check"/);
  assert.match(html, /data-status-section-detail="go-live"/);
  assert.doesNotMatch(html, /full-restore-drill/);
  const domainStatusHtml = await getText(`${baseUrl}/?section=status&statusCategory=domain-edge`);
  assert.match(domainStatusHtml, /data-status-section-detail="domain-edge"/);
  assert.match(domainStatusHtml, /portal-through-waf|cloudflare-access-admin/);
  assert.doesNotMatch(domainStatusHtml, /full-restore-drill/);
  const backupStatusHtml = await getText(`${baseUrl}/?section=status&statusCategory=backup-dr`);
  assert.match(backupStatusHtml, /data-status-section-detail="backup-dr"/);
  assert.match(backupStatusHtml, /full-restore-drill|Backup\/restore off-site/);
  assert.doesNotMatch(backupStatusHtml, /cloudflare-access-admin/);
  const githubStatusHtml = await getText(`${baseUrl}/?section=status&statusCategory=github-release`);
  assert.match(githubStatusHtml, /data-status-section-detail="github-release"/);
  assert.match(githubStatusHtml, /github-actions-run-evidence|GitHub Actions runtime/);
  assert.match(backupStatusHtml, /offsite-backup-restore-rpo-rto/);
  assert.doesNotMatch(html, /Non pronto per andare online|Pronto per andare online/);
  assert.doesNotMatch(html, /Riepilogo go live/);
  assert.doesNotMatch(html, /Verdetto/);
  assert.doesNotMatch(html, /Controlli OK/);
  assert.doesNotMatch(html, /Aggiorna/);
  assert.doesNotMatch(html, /Dati tecnici/);
  assert.doesNotMatch(html, /Dati stato/);
  assert.doesNotMatch(html, /Copia controllo/);
  assert.doesNotMatch(html, /data-copy-command="sh \.\/scripts\/production-go-no-go\.sh"/);
  assert.doesNotMatch(html, /Control Center avviato/);
  assert.doesNotMatch(html, /Asset Portal serviti/);
  assert.doesNotMatch(html, /Control Center local UI contract/);
  assert.doesNotMatch(html, /Simple Mode operational MVP/);
  assert.doesNotMatch(html, /Advanced Mode enterprise sections/);
  assert.match(html, /Go live e decisione/);
  assert.match(html, /<details class="ops-status-check-row/);
  assert.match(html, /ops-status-check-details/);
  assert.doesNotMatch(html, /ops-status-check-copy/);
  assert.match(html, /\/assets\/control-center\/control-center\.css/);
  assert.match(html, /\/assets\/control-center\/control-center\.js/);
  assert.match(html, /cc-app-shell/);
  assert.match(html, /ops-topbar/);
  assert.match(html, /ops-sidebar/);
  assert.match(html, /ops-nav/);
  assert.match(html, /data-ops-nav-group="status"/);
  assert.match(html, /ops-nav-panel-status/);
  assert.match(html, /data-ops-nav-group="projects" data-ops-nav-expanded="false"/);
  assert.match(html, /id="ops-nav-panel-projects" aria-hidden="true"/);
  assert.match(html, /href="\/\?section=projects&amp;project=node-demo"/);
  assert.doesNotMatch(html, /class="ops-nav-main[^"]*"[^>]*aria-current="page"/);
  assert.match(html, /class="ops-nav-subitem active [^"]*" aria-current="page" data-status-category-card="go-live"/);
  assert.doesNotMatch(html, /class="ops-nav-main[^"]*"[^>]*href=/);
  assert.match(html, /data-status-section-detail="go-live"/);
  assert.doesNotMatch(html, /ops-status-pill/);
  assert.doesNotMatch(html, /class="cc-tabs"/);
  assert.doesNotMatch(html, /Open navigation/);
  assert.doesNotMatch(html, /Search Control Center/);
  assert.doesNotMatch(html, /aria-label="Help"/);
  assert.doesNotMatch(html, /aria-label="Settings"/);
  assert.doesNotMatch(html, /Platform Documentation/);
  assert.doesNotMatch(html, /Runbook, security, readiness and service documentation/);
  assert.doesNotMatch(html, /href="\/\?mode=simple/);
  assert.doesNotMatch(html, /href="\/\?mode=advanced/);
  assert.match(html, /data-cc-theme="light"/);
  assert.doesNotMatch(html, /data-cc-theme="dark"/);
  assert.doesNotMatch(html, /onchange=/);
  assert.equal(html.includes(["/assets", "node-demo", "ui"].join("/") + "/"), false);
  assert.doesNotMatch(html, new RegExp(`${["ui", "shell"].join("-")}|${["pill", "sidebar", "nav"].join("-")}|${["pill", "tabs"].join("-")}`));
  assert.match(html, /ops-brand/);
  assert.doesNotMatch(html, /phpmyadmin\.localhost\.com/);
  assert.doesNotMatch(html, /grafana\.localhost\.com/);
  const pageResponse = await fetch(`${baseUrl}/`);
  const pageEtag = pageResponse.headers.get("etag");
  assert.match(pageEtag || "", /^"[A-Za-z0-9_-]+"$/);
  assert.match(pageResponse.headers.get("cache-control") || "", /private, max-age=0, must-revalidate/);
  const pageRevalidated = await fetch(`${baseUrl}/`, { headers: { "if-none-match": pageEtag } });
  assert.equal(pageRevalidated.status, 304);

  const docsHtml = await getTextWithHost(`${baseUrl}/`, "docs.localhost.com");
  assert.match(docsHtml, /Platform Documentation/);
  assert.match(docsHtml, /Runbook, security, readiness and service documentation/);
  assert.match(docsHtml, /README\.md/);
  assert.match(docsHtml, /RUNBOOK\.md/);
  assert.doesNotMatch(docsHtml, /Admin Control Center/);
  const readmeHtml = await getTextWithHost(`${baseUrl}/docs/README.md`, "docs.localhost.com");
  assert.match(readmeHtml, /README\.md/);
  assert.match(readmeHtml, /Platform Infrastructure|URL locali/);

  const localStyles = await getText(`${baseUrl}/assets/control-center/control-center.css`);
  const serverSource = readFileSync(path.join(infraRoot, "control-center", "server.mjs"), "utf8");
  const styleResponse = await fetch(`${baseUrl}/assets/control-center/control-center.css`);
  const styleEtag = styleResponse.headers.get("etag");
  assert.match(styleEtag || "", /^"[A-Za-z0-9_-]+"$/);
  assert.match(styleResponse.headers.get("cache-control") || "", /public, max-age=3600, must-revalidate/);
  const styleRevalidated = await fetch(`${baseUrl}/assets/control-center/control-center.css`, { headers: { "if-none-match": styleEtag } });
  assert.equal(styleRevalidated.status, 304);
  assert.match(localStyles, /--cc-bg/);
  assert.match(localStyles, /--cc-surface-raised/);
  assert.match(localStyles, /--cc-line/);
  assert.match(localStyles, /\.cc-app-shell/);
  assert.doesNotMatch(localStyles, /data-cc-preloading|cc-preload-screen|ccPreloadSpin/);
  assert.match(localStyles, /\.cc-app-shell\[aria-busy="true"\] \.ops-page\s*\{[^}]*opacity:\s*\.72/s);
  assert.match(localStyles, /\.ops-shell/);
  assert.match(localStyles, /\.ops-sidebar/);
  assert.match(localStyles, /\.ops-sidebar\s*\{[^}]*overflow-anchor:\s*none/s);
  assert.match(localStyles, /\.ops-nav/);
  assert.match(localStyles, /\.ops-nav\s*\{[^}]*overflow-anchor:\s*none/s);
  assert.match(localStyles, /\.ops-nav-group/);
  assert.match(localStyles, /\.ops-nav-sublist/);
  assert.match(localStyles, /\.ops-nav-subitem/);
  assert.match(localStyles, /\.ops-nav-subdot\.good/);
  assert.match(localStyles, /\.ops-nav-row/);
  assert.match(localStyles, /\.ops-nav-chevron/);
  assert.match(localStyles, /\.ops-nav-chevron \.fa-icon\s*\{[^}]*transform:\s*rotate\(-90deg\)/s);
  assert.match(localStyles, /\.ops-nav-chevron \.fa-icon\s*\{[^}]*transition:\s*transform 220ms var\(--cc-ease\)/s);
  assert.match(localStyles, /\.ops-nav-group\.expanded \.ops-nav-chevron \.fa-icon\s*\{[^}]*transform:\s*rotate\(0deg\)/s);
  assert.doesNotMatch(localStyles, /\.section-projects \.ops-nav\s*\{/);
  assert.match(localStyles, /background:\s*#bfdbfe/);
  assert.match(localStyles, /\.ops-nav-pill\s*\{[^}]*background:\s*#bfdbfe/s);
  assert.match(localStyles, /\.ops-nav-pill\s*\{[^}]*border-radius:\s*999px/s);
  assert.match(localStyles, /\.ops-nav-pill\s*\{[^}]*opacity:\s*1/s);
  assert.match(localStyles, /\.ops-nav-pill\s*\{[^}]*transform:\s*translate3d\(0, 0, 0\)/s);
  assert.match(localStyles, /\.ops-nav-pill\s*\{[^}]*transition:\s*transform 320ms var\(--cc-ease\), width 320ms var\(--cc-ease\), height 320ms var\(--cc-ease\)/s);
  assert.match(localStyles, /\.ops-nav-pill\s*\{[^}]*will-change:\s*transform,\s*width,\s*height/s);
  assert.match(localStyles, /\.ops-nav\[data-nav-pill-instant="true"\] \.ops-nav-pill\s*\{[^}]*transition:\s*none/s);
  assert.doesNotMatch(localStyles, /\.ops-nav\[data-nav-pill-ready="true"\] \.ops-nav-pill\s*\{[^}]*opacity/s);
  assert.doesNotMatch(localStyles, /\.ops-nav-pill\s*\{[^}]*transition:[^}]*opacity/s);
  assert.doesNotMatch(localStyles, /\.ops-nav-pill\s*\{[^}]*will-change:[^}]*opacity/s);
  assert.doesNotMatch(localStyles, /\.ops-nav::before\s*\{/);
  assert.doesNotMatch(localStyles, /data-nav-indicator/);
  assert.match(localStyles, /\.ops-nav\[data-ops-nav-restoring="true"\] \.ops-nav-sublist\s*\{[^}]*transition:\s*none/s);
  assert.doesNotMatch(localStyles, /data-ops-nav-has-active-child="true"\]\s*>\s*\.ops-nav-row\s*>\s*\.ops-nav-main/);
  assert.doesNotMatch(localStyles, /\.ops-nav-subitem::before/);
  assert.doesNotMatch(localStyles, /data-nav-pill-fade/);
  assert.doesNotMatch(localStyles, /@keyframes opsNavPillFadeIn/);
  assert.match(localStyles, /\.ops-nav a,\s*\.ops-nav-main\s*\{[^}]*border:\s*0/s);
  assert.match(localStyles, /\.ops-nav a,\s*\.ops-nav-main\s*\{[^}]*border-radius:\s*999px/s);
  assert.match(localStyles, /\.ops-nav a,\s*\.ops-nav-main\s*\{[^}]*min-height:\s*48px/s);
  assert.match(localStyles, /\.ops-nav-subitem\s*\{[^}]*min-height:\s*44px/s);
  assert.match(localStyles, /\.ops-nav-subitem\s*\{[^}]*padding:\s*0 12px/s);
  assert.match(localStyles, /\.ops-nav a\.active\s*\{[^}]*color:\s*#174ea6/s);
  assert.match(localStyles, /\.ops-nav-sublist\s*\{[^}]*box-sizing:\s*border-box/s);
  assert.match(localStyles, /\.ops-nav-sublist\s*\{[^}]*padding:\s*2px 0 4px 18px/s);
  assert.match(localStyles, /\.ops-nav-sublist\s*\{[^}]*transition:\s*max-height 260ms var\(--cc-ease\), opacity 200ms var\(--cc-ease\)/s);
  assert.doesNotMatch(localStyles, /\.ops-nav-sublist\s*\{[^}]*transition:[^}]*padding/s);
  assert.match(localStyles, /\.ops-nav-group\.expanded \.ops-nav-sublist\s*\{[^}]*max-height:\s*var\(--ops-nav-panel-height\)/s);
  assert.match(localStyles, /\.ops-nav-group\.expanded \.ops-nav-sublist\s*\{[^}]*overflow:\s*hidden/s);
  assert.doesNotMatch(localStyles, /\.ops-nav-group\.expanded \.ops-nav-sublist\s*\{[^}]*padding/s);
  assert.doesNotMatch(localStyles, /\.ops-nav:not\(\[data-nav-pill-ready="true"\]\) a\.active/);
  assert.doesNotMatch(localStyles, /\.ops-nav a:hover\s*\{/);
  assert.doesNotMatch(localStyles, /\.ops-nav a\.active:hover\s*\{/);
  assert.match(localStyles, /\.ops-table/);
  assert.match(localStyles, /\.ops-metrics/);
  assert.match(localStyles, /\.ops-project-list/);
  assert.match(localStyles, /\.ops-project-row/);
  assert.doesNotMatch(localStyles, /\.ops-project-row:hover/);
  assert.doesNotMatch(localStyles, /\.ops-project-row-host a:hover/);
  assert.match(localStyles, /\.ops-project-state-dot/);
  assert.match(localStyles, /\.ops-project-state-dot\.good/);
  assert.match(localStyles, /\.ops-project-state-dot\.warn/);
  assert.match(localStyles, /\.ops-project-state-dot\.bad/);
  assert.match(localStyles, /\.ops-page\s*\{[^}]*align-content:\s*start/s);
  assert.match(localStyles, /\.ops-section\s*\{[^}]*grid-auto-rows:\s*max-content/s);
  assert.match(localStyles, /\.ops-project-detail-screen\s*\{[^}]*align-content:\s*start/s);
  assert.match(localStyles, /\.ops-shell\s*\{[^}]*--ops-sidebar-width:\s*264px/s);
  assert.match(localStyles, /\.ops-layout\s*\{[^}]*padding-left:\s*var\(--ops-sidebar-width\)/s);
  assert.match(localStyles, /\.ops-sidebar\s*\{[^}]*background:\s*transparent/s);
  assert.match(localStyles, /\.ops-sidebar\s*\{[^}]*position:\s*fixed/s);
  assert.match(localStyles, /\.ops-sidebar\s*\{[^}]*width:\s*var\(--ops-sidebar-width\)/s);
  assert.match(localStyles, /\.ops-sidebar\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(localStyles, /\.ops-sidebar\s*\{[^}]*scrollbar-width:\s*thin/s);
  assert.match(localStyles, /scrollbar-color:\s*rgba\(30,\s*41,\s*59,\s*\.18\)\s+transparent/);
  assert.match(localStyles, /\.ops-sidebar::-webkit-scrollbar\s*\{[^}]*width:\s*5px/s);
  assert.match(localStyles, /\.ops-status-workspace\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)/s);
  assert.doesNotMatch(localStyles, /\.ops-status-section-list/);
  assert.doesNotMatch(localStyles, /\.ops-status-section-row\.active/);
  assert.match(localStyles, /\.ops-status-check-summary\s*\{[^}]*grid-template-columns:\s*12px\s*minmax\(0,\s*1fr\)\s*auto\s*auto/s);
  assert.match(localStyles, /\.ops-status-check-run/);
  assert.doesNotMatch(localStyles, /padding-top:\s*190px/);
  assert.doesNotMatch(localStyles, /padding-top:\s*236px/);
  assert.match(localStyles, /\.ops-project-row-host a/);
  assert.match(localStyles, /white-space:\s*nowrap/);
  assert.match(localStyles, /\.ops-project-detail-screen/);
  assert.doesNotMatch(localStyles, /\.ops-project-detail-back/);
  assert.match(localStyles, /\.ops-file-explorer/);
  assert.match(localStyles, /\.ops-file-grid/);
  assert.match(localStyles, /\.ops-file-workspace\s*\{[^}]*height:\s*clamp\(260px,\s*calc\(100vh - 380px\),\s*460px\)/s);
  assert.match(localStyles, /\.ops-file-grid\s*\{[^}]*height:\s*100%/s);
  assert.match(localStyles, /\.ops-project-detail-focus\s*\{[^}]*align-items:\s*stretch/s);
  assert.match(localStyles, /\.ops-file-explorer\s*\{[^}]*background:\s*#ffffff/s);
  assert.match(localStyles, /\.ops-file-search\s*\{[^}]*background:\s*#f1f5f9/s);
  assert.match(localStyles, /\.ops-file-search\s*\{[^}]*width:\s*clamp\(150px,\s*16vw,\s*230px\)/s);
  assert.match(localStyles, /\.ops-file-search input\s*\{[^}]*border:\s*0/s);
  assert.match(localStyles, /\.ops-file-search input\s*\{[^}]*box-shadow:\s*none/s);
  assert.match(localStyles, /\.ops-file-search input::-webkit-search-cancel-button/);
  assert.match(localStyles, /\.ops-file-commandbar \[data-file-refresh-action\]\s*\{[^}]*background:\s*#f1f5f9/s);
  assert.match(localStyles, /\.ops-file-commandbar\s*\{[^}]*min-width:\s*0/s);
  assert.match(localStyles, /\.ops-file-workspace\s*\{[^}]*background:\s*#f1f5f9/s);
  assert.match(localStyles, /\.ops-file-tile\[hidden\]\s*\{[^}]*display:\s*none/s);
  assert.match(localStyles, /\.ops-project-detail-focus\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\)/s);
  assert.match(localStyles, /#project-backups,\s*#project-databases\s*\{[^}]*align-self:\s*stretch/s);
  assert.match(localStyles, /#project-backups,\s*#project-databases\s*\{[^}]*grid-template-rows:\s*auto minmax\(0,\s*1fr\)/s);
  assert.match(localStyles, /#project-backups,\s*#project-databases\s*\{[^}]*height:\s*clamp\(380px,\s*44vh,\s*560px\)/s);
  assert.match(localStyles, /\.ops-project-backup-list\s*\{[^}]*background:\s*#f1f5f9/s);
  assert.match(localStyles, /\.ops-project-backup-list\s*\{[^}]*height:\s*100%/s);
  assert.match(localStyles, /\.ops-project-backup-list\s*\{[^}]*max-height:\s*100%/s);
  assert.match(localStyles, /\.ops-project-backup-row\s*\{[^}]*background:\s*#ffffff/s);
  assert.match(localStyles, /\.ops-project-backup-row > span:last-child\s*\{[^}]*min-width:\s*0/s);
  assert.match(localStyles, /\.ops-button,\s*\.ops-icon-button\s*\{[^}]*border-radius:\s*999px/s);
  assert.match(localStyles, /\.ops-project-backup-head-form\s*\{[^}]*flex:\s*0 0 auto/s);
  assert.match(localStyles, /\.ops-project-backup-head-form \.ops-button\s*\{[^}]*min-height:\s*38px/s);
  assert.match(localStyles, /\.ops-project-backup-restore-form\s*\{[^}]*align-items:\s*center/s);
  assert.match(localStyles, /\.ops-project-backup-restore-form\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\) minmax\(150px,\s*\.45fr\) auto/s);
  assert.match(localStyles, /\.ops-project-select\s*\{[^}]*display:\s*block/s);
  assert.match(localStyles, /\.ops-project-select select\s*\{[^}]*border-radius:\s*999px/s);
  assert.match(localStyles, /\.ops-project-select select\s*\{[^}]*-webkit-appearance:\s*none/s);
  assert.match(localStyles, /\.ops-project-select select\s*\{[^}]*appearance:\s*none/s);
  assert.match(localStyles, /\.ops-project-select select\s*\{[^}]*padding:\s*0 38px 0 14px/s);
  assert.match(localStyles, /\.ops-project-select-chevron\s*\{[^}]*position:\s*absolute/s);
  assert.match(localStyles, /\.ops-project-select-chevron\s*\{[^}]*right:\s*14px/s);
  assert.match(localStyles, /\.ops-project-select-chevron\s*\{[^}]*top:\s*50%/s);
  assert.match(localStyles, /\.ops-project-select-chevron \.fa-icon\s*\{[^}]*height:\s*12px/s);
  assert.match(localStyles, /\.ops-project-backup-restore-form \.ops-project-select select\s*\{[^}]*background:\s*#f1f5f9/s);
  assert.doesNotMatch(localStyles, /ops-project-backup-fixed-scope/);
  assert.match(localStyles, /\.ops-project-database-list\s*\{[^}]*background:\s*transparent/s);
  assert.match(localStyles, /\.ops-project-database-list\s*\{[^}]*height:\s*100%/s);
  assert.match(localStyles, /\.ops-project-database-list\s*\{[^}]*max-height:\s*100%/s);
  assert.match(localStyles, /\.ops-project-database-list\s*\{[^}]*overflow:\s*auto/s);
  assert.match(localStyles, /\.ops-project-database-list::-webkit-scrollbar[\s\S]*width:\s*3px/s);
  assert.match(localStyles, /\.ops-project-database-list\s*\{[^}]*padding:\s*0/s);
  assert.match(localStyles, /\.ops-project-database-row\s*\{[^}]*background:\s*#f1f5f9/s);
  assert.match(localStyles, /\.ops-project-database-edit-form\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1\.1fr\) minmax\(0,\s*\.9fr\) auto/s);
  assert.match(localStyles, /\.ops-project-database-edit-form \+ \.ops-project-database-edit-form\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s+auto/s);
  assert.match(localStyles, /\.ops-project-database-create-form\s*\{[^}]*background:\s*#f1f5f9/s);
  assert.match(localStyles, /\.ops-button\.compact\s*\{[^}]*border-radius:\s*999px/s);
  assert.match(localStyles, /#project-file-manager\s*\{[^}]*grid-column:\s*1 \/ -1/s);
  assert.match(localStyles, /#project-backups\s*\{[^}]*grid-column:\s*1/s);
  assert.match(localStyles, /#project-databases\s*\{[^}]*grid-column:\s*2/s);
  assert.match(localStyles, /#project-resources\s*\{[^}]*grid-column:\s*1 \/ -1/s);
  assert.match(localStyles, /\.ops-project-detail-resource-grid\s*\{[^}]*grid-template-columns:\s*repeat\(4,\s*minmax\(0,\s*1fr\)\)/s);
  assert.match(localStyles, /\.ops-file-tile\.selected/);
  assert.match(localStyles, /\.ops-file-context-menu/);
  assert.match(localStyles, /\.ops-file-tile-icon\s*\{[^}]*background:\s*#2563eb/s);
  assert.match(localStyles, /\.ops-file-tile\.file \.ops-file-tile-icon\s*\{[^}]*background:\s*#344054/s);
  assert.match(localStyles, /\.ops-project-detail-item-icon\s*\{[^}]*background:\s*#175cd3/s);
  assert.doesNotMatch(localStyles, /\.ops-project-file-table/);
  const localServer = readFileSync(path.join(infraRoot, "control-center", "server.mjs"), "utf8");
  assert.doesNotMatch(localServer, /renderProjectSelect\("status",\s*"Stato database"/);
  assert.match(localServer, /renderProjectSelect\("engine",\s*"Motore database"/);
  assert.match(localServer, /renderProjectSelect\("restoreMode",\s*"Contenuto restore"/);
  assert.match(localStyles, /\.ops-icon-button/);
  assert.match(localStyles, /box-shadow:\s*var\(--cc-focus\)/);
  assert.match(localStyles, /color-scheme:\s*light/);
  assert.doesNotMatch(localStyles, /color-scheme:\s*dark/);
  assert.doesNotMatch(localStyles, /gradient/i);
  const localClient = await getText(`${baseUrl}/assets/control-center/control-center.js`);
  assert.match(localClient, /history\.pushState/);
  assert.match(localClient, /fetch\(/);
  assert.match(localClient, /Accept", "text\/html,\*\/\*;q=0\.8"/);
  assert.doesNotMatch(localClient, /application\/json;q=/);
  assert.match(localClient, /addEventListener\("submit"/);
  assert.match(localClient, /addEventListener\("popstate"/);
  assert.match(localClient, /htmlCache/);
  assert.match(localClient, /var cacheLimit = 32/);
  assert.match(localClient, /var cacheTtlMs = 15000/);
  assert.match(localClient, /var prefetchTimeoutMs = 1200/);
  assert.match(localClient, /var formSubmissions = new WeakSet\(\)/);
  assert.match(localClient, /var navigationSequence = 0/);
  assert.match(localClient, /If-None-Match/);
  assert.match(localClient, /response\.status === 304/);
  assert.doesNotMatch(localClient, /preloadPageLimit|preloadWorkerCount|stripInitialPreloadHtml|data-cc-preloading|cc-preload-screen/);
  assert.match(localClient, /updateStableElement\(currentSidebar, nextSidebar, \{ preserveNavPill: true \}\)/);
  assert.match(localClient, /updateStableElement\(currentPage, nextPage\)/);
  assert.match(localClient, /nextPill\.replaceWith\(currentPill\)/);
  assert.doesNotMatch(localClient, /currentSidebar\.replaceWith/);
  assert.doesNotMatch(localClient, /currentPage\.replaceWith/);
  assert.match(localClient, /matchMedia\("\(max-width: 860px\)"\)/);
  assert.match(localStyles, /@media \(max-width: 860px\)[\s\S]*?\.ops-sidebar\s*\{[^}]*max-height:\s*min\(46dvh, 420px\)[^}]*position:\s*sticky/s);
  assert.match(localStyles, /@media \(max-width: 860px\)[\s\S]*?\.ops-nav\s*\{[^}]*grid-template-columns:\s*1fr/s);
  assert.match(serverSource, /CONTROL_CENTER_CONTEXT_CACHE_TTL_MS/);
  assert.match(serverSource, /req\.method !== "GET"\) invalidateControlContextCache\(\)/);
  assert.match(serverSource, /req\.method === "GET" && !url\.pathname\.startsWith\("\/control\/"\)\s*\? await buildCachedContext/);
  assert.match(serverSource, /controlContextCache\.pending && controlContextCache\.key === key/);
  assert.match(serverSource, /context\.statusRows = opsStatusRows\(context\)/);
  assert.match(serverSource, /function statusRowsForContext\(context\)/);
  assert.match(localClient, /if \(sequence !== navigationSequence\) return true/);
  assert.match(localClient, /ccBootId/);
  assert.match(localClient, /data-copy-command/);
  assert.match(localClient, /fitSingleLineText/);
  assert.match(localClient, /data-project-row-link/);
  assert.match(localClient, /data-fit-single-line/);
  assert.match(localClient, /startFileManagers/);
  assert.match(localClient, /data-file-refresh-action/);
  assert.match(localClient, /data-file-search/);
  assert.match(localClient, /applyFileSearch/);
  assert.match(localClient, /var haystack = payload\.name\.toLowerCase\(\);/);
  assert.doesNotMatch(localClient, /\[payload\.name,\s*payload\.path,\s*payload\.type\]/);
  assert.match(localClient, /fileManagerRefreshInFlight/);
  assert.match(localClient, /refreshFileManager/);
  assert.match(localClient, /previousScrollTop/);
  assert.match(localClient, /nextGrid\.scrollTop = previousScrollTop/);
  assert.match(localClient, /data-file-manager-refresh-url/);
  assert.doesNotMatch(localClient, /fileManagerLiveTimer/);
  assert.doesNotMatch(localClient, /setInterval\(refreshFileManager/);
  assert.match(localClient, /data-file-entry/);
  assert.match(localClient, /data-file-menu-action/);
  assert.match(localClient, /addEventListener\("dblclick"/);
  assert.match(localClient, /addEventListener\("contextmenu"/);
  assert.match(localClient, /opsNavLastPillRect/);
  assert.match(localClient, /opsNavPillFrame/);
  assert.match(localClient, /opsNavLayoutFrame/);
  assert.match(localClient, /pendingSidebarScrollTop/);
  assert.match(localClient, /pendingSidebarScrollAt/);
  assert.doesNotMatch(localClient, /opsNavPendingTargetKey/);
  assert.doesNotMatch(localClient, /opsNavPreMoved/);
  assert.doesNotMatch(localClient, /preloadStarted/);
  assert.match(localClient, /prefetchInFlight/);
  assert.match(localClient, /getBoundingClientRect/);
  assert.match(localClient, /opsNavPixel/);
  assert.match(localClient, /usableOpsNavPillTarget/);
  assert.doesNotMatch(localClient, /opsNavUrlKey/);
  assert.doesNotMatch(localClient, /opsNavLinkKey/);
  assert.match(localClient, /opsNavActiveItem/);
  assert.match(localClient, /opsNavPillTarget/);
  assert.match(localClient, /opsNavPillRectToTarget/);
  assert.match(localClient, /writeOpsNavPill/);
  assert.match(localClient, /applyOpsNavPill/);
  assert.match(localClient, /prefetchHtml/);
  assert.match(localClient, /controller\.abort\(\)/);
  assert.match(localClient, /signal: controller\.signal/);
  assert.match(localClient, /window\.clearTimeout\(timeout\)/);
  assert.match(localClient, /cachedPage/);
  assert.doesNotMatch(localClient, /collectPageUrlsForPreload|discoverPreloadUrls|pageUrlsForPreload|preloadControlCenterPages|finishControlCenterPreload|startControlCenterPreload|scheduleControlCenterPreload/);
  assert.match(localClient, /positionOpsNavPill/);
  assert.match(localClient, /captureOpsNavPillRect/);
  assert.match(localClient, /moveOpsNavPillTowardLink/);
  assert.match(localClient, /trackOpsNavPillDuringLayout/);
  assert.match(localClient, /currentSidebarScrollTop/);
  assert.match(localClient, /restoreSidebarScrollTop/);
  assert.match(localClient, /rememberSidebarScrollBeforePointer/);
  assert.match(localClient, /consumePendingSidebarScrollTop/);
  assert.match(localClient, /event\.target\.closest\("\.ops-nav-subitem\[href\]"\)/);
  assert.match(localClient, /var previousSidebarScrollTop = options && typeof options\.sidebarScrollTop === "number" \? options\.sidebarScrollTop : currentSidebarScrollTop\(\)/);
  assert.match(localClient, /var sidebarScrollTop = consumePendingSidebarScrollTop\(\)/);
  assert.match(localClient, /navigate\(url, \{ history: "push", sidebarScrollTop: sidebarScrollTop \}\)/);
  assert.match(localClient, /document\.addEventListener\("pointerdown", rememberSidebarScrollBeforePointer, \{ capture: true \}\)/);
  assert.match(localClient, /captureOpsNavExpandedState/);
  assert.match(localClient, /var previousOpsNavExpandedState = captureOpsNavExpandedState\(\)/);
  assert.match(localClient, /restoreSidebarState\(\{ instantOpsNav: true, opsNavExpandedState: previousOpsNavExpandedState \}\)/);
  assert.match(localClient, /var preserved = options && options\.expandedState && typeof options\.expandedState === "object" \? options\.expandedState : \{\}/);
  assert.match(localClient, /var opsStateChanged = false/);
  assert.match(localClient, /if \(hasActiveItem && key && opsState\[key\] !== true\) \{/);
  assert.match(localClient, /opsState\[key\] = true;\s*opsStateChanged = true;/);
  assert.match(localClient, /if \(opsStateChanged\) \{\s*state\.opsNav = opsState;\s*writeSidebarState\(state\);/);
  assert.match(localClient, /hasActiveItem \? true : compactNavigation \? false : typeof preserved\[key\] === "boolean" \? preserved\[key\] : typeof opsState\[key\] === "boolean" \? opsState\[key\] : current/);
  assert.match(localClient, /expandedState: options && options\.opsNavExpandedState/);
  assert.match(localClient, /activeNavItemInGroup/);
  assert.match(localClient, /groupContainsActiveNavItem/);
  assert.doesNotMatch(localClient, /navIndicator/);
  assert.doesNotMatch(localClient, /NavIndicator/);
  assert.doesNotMatch(localClient, /data-nav-indicator/);
  assert.doesNotMatch(localClient, /window\.getComputedStyle\(nav, "::before"\)/);
  assert.doesNotMatch(localClient, /fadeOutNavIndicatorForSectionChange/);
  assert.match(localClient, /syncOpsNavPanelHeight/);
  assert.match(localClient, /restoreOpsNavState/);
  assert.match(localClient, /dataset\.opsNavRestoring = "true"/);
  assert.match(localClient, /toggleOpsNavGroup/);
  assert.match(localClient, /group\.dataset\.opsNavLocked = locked \? "true" : "false"/);
  assert.match(localClient, /toggle\.setAttribute\("aria-disabled", "true"\)/);
  assert.match(localClient, /toggle\.removeAttribute\("aria-disabled"\)/);
  assert.match(localClient, /locked \? "Sezione attuale: " \+ label/);
  assert.doesNotMatch(localClient, /fadeNavPillOut/);
  assert.doesNotMatch(localClient, /resetNavPillFade/);
  assert.doesNotMatch(localClient, /data-nav-pill-fade/);
  assert.match(localClient, /data-ops-nav-toggle/);
  assert.match(localClient, /\.ops-nav-subitem\[aria-current='page'\], \.ops-nav-subitem\.active/);
  assert.doesNotMatch(localClient, /group\.querySelector\("\.ops-nav-main"\)/);
  assert.doesNotMatch(localClient, /isSubitem\s*\?\s*navRect\.width\s*:\s*activeRect\.width/);
  assert.doesNotMatch(localClient, /await sleep\(190\)/);
  assert.doesNotMatch(localClient, /await fadeOutNavIndicatorForSectionChange\(url\)/);
  assert.match(localClient, /restoreSidebarState\(\{ instantOpsNav: true \}\)/);
  assert.match(localClient, /new EventSource\("\/control\/v1\/status\/events\/stream\?runId="/);
  assert.match(localClient, /event\.type === "check-completed"/);
  assert.doesNotMatch(localClient, /animateStatusRun|statusStepDelay|await sleep\(delay\)/);
  assert.match(localClient, /prefetchHtml\(url\)/);
  assert.doesNotMatch(localClient, /function prefetch\(url\)[\s\S]*requestHtml\(url, \{ method: "GET" \}\)/);
  assert.doesNotMatch(localClient, /window\.history\.replaceState\(\{ ccDynamic: true \}[\s\S]*restoreSidebarState\(\);\s*positionOpsNavPill\(\{ instant: true \}\)/);
  assert.match(localClient, /var previousPillRect = captureOpsNavPillRect\(\) \|\| opsNavLastPillRect/);
  assert.match(localClient, /restoreSidebarScrollTop\(previousSidebarScrollTop\)/);
  assert.doesNotMatch(localClient, /alreadyMovedToTarget/);
  assert.match(localClient, /positionOpsNavPill\(\{ fromViewportRect: previousPillRect \}\)/);
  assert.match(localClient, /opsNavLastPillRect = null/);
  assert.match(localClient, /positionOpsNavPill\(\{ instant: true \}\)/);
  assert.match(localClient, /var active = options && options\.item \? options\.item : opsNavActiveItem\(nav\)/);
  assert.match(localClient, /captureOpsNavPillRect\(\);\s*setBusy\(true\);/);
  assert.match(localClient, /var clickedLink = event\.target\.closest\("a\[href\]"\)/);
  assert.match(localClient, /moveOpsNavPillTowardLink\(clickedLink\)/);
  assert.match(localClient, /trackOpsNavPillDuringLayout\(activeItem, 320\)/);
  assert.match(localClient, /function trackOpsNavPillDuringLayout\(activeItem, duration\)/);
  assert.match(localClient, /var active = activeItem && activeItem\.isConnected \? activeItem : opsNavActiveItem\(nav\)/);
  assert.match(localClient, /positionOpsNavPill\(\{ item: active \}\)/);
  assert.doesNotMatch(localClient, /var rect = link\.getBoundingClientRect\(\);\s*if \(rect\.width && rect\.height\) \{\s*opsNavLastPillRect =/);
  assert.match(localClient, /if \(hasActiveItem && currentExpanded\) \{/);
  assert.match(localClient, /opsState\[key\] = true;\s*state\.opsNav = opsState;\s*writeSidebarState\(state\);\s*setOpsNavGroupExpanded\(group, true\);/);
  assert.match(localClient, /var activeItem = opsNavActiveItem\(document\.querySelector\("\.ops-nav"\)\);\s*captureOpsNavPillRect\(\);\s*setOpsNavGroupExpanded\(group, expanded\);\s*trackOpsNavPillDuringLayout\(activeItem, 320\);/);
  assert.doesNotMatch(localClient, /if \(expanded\) \{\s*showNavIndicatorForGroup\(group\);\s*\} else \{\s*hideNavIndicatorForGroup\(group\);/);
  assert.doesNotMatch(localClient, /if \(!expanded && hasActiveItem\)/);
  assert.doesNotMatch(localClient, /setOpsNavGroupExpanded\(group, expanded\);\s*updateOpsNavIndicator\(true\);/);
  assert.match(localClient, /data-status-run-console/);
  assert.match(localClient, /data-status-run-inline/);
  assert.match(localClient, /statusCategory/);
  assert.match(localClient, /body\.set\("runId", runId\)/);
  assert.match(localClient, /Non eseguito in questo run/);
  assert.match(localClient, /setAttribute\("open", ""\)/);
  assert.match(localClient, /navigator\.clipboard\.writeText/);
  assert.doesNotMatch(localClient, /window\.location\.reload/);
  const localUiPackage = await getJson(`${baseUrl}/control/ui-package`);
  assert.equal(localUiPackage.name, "@platform/control-center-local-ui");
  assert.equal(localUiPackage.controlCenterProject, "@platform/control-center");
  assert.equal(localUiPackage.controlCenterPackageLoaded, true);
  assert.equal(localUiPackage.declaredDependency, "none");
  assert.equal(localUiPackage.packageMountedInControlCenterProject, true);
  assert.equal(localUiPackage.usingVendoredPackage, false);
  assert.equal(localUiPackage.apiManifestLoaded, true);
  assert.equal(localUiPackage.hostInstallRequired, false);
  assert.equal(localUiPackage.entrypoints.includes("/assets/control-center/control-center.css"), true);
  assert.equal(localUiPackage.entrypoints.includes("/assets/control-center/control-center.js"), true);
  assert.equal(localUiPackage.servedAssets.includes("/assets/control-center/control-center.css"), true);
  assert.equal(localUiPackage.servedAssets.includes("/assets/control-center/control-center.js"), true);
  assert.equal(localUiPackage.coreExports.includes("OperationsShell"), true);
  assert.equal(localUiPackage.coreExports.includes("ProjectFileBrowser"), true);
  assert.equal(localUiPackage.coreExports.includes("ActivityTable"), false);
  assert.equal(localUiPackage.cssVariablePrefix, "--cc-");
  assert.deepEqual(localUiPackage.missingRequiredExports, []);

  const projectsOpsHtml = await getText(`${baseUrl}/?section=projects`);
  assert.match(projectsOpsHtml, /\/assets\/control-center\/control-center\.css\?v=/);
  assert.match(projectsOpsHtml, /\/assets\/control-center\/control-center\.js\?v=/);
  assert.match(projectsOpsHtml, /PHP Apache/);
  assert.match(projectsOpsHtml, /Node\/Next/);
  assert.match(projectsOpsHtml, /Runtime/);
  assert.match(projectsOpsHtml, /ops-project-list/);
  assert.match(projectsOpsHtml, /data-ops-nav-group="projects" data-ops-nav-expanded="true" data-ops-nav-has-active-child="true" data-ops-nav-locked="true"/);
  assert.match(projectsOpsHtml, /id="ops-nav-panel-projects" aria-hidden="false"/);
  assert.match(projectsOpsHtml, /aria-label="Sezione attuale: Applicazioni" aria-expanded="true" aria-controls="ops-nav-panel-projects" aria-disabled="true"/);
  assert.match(projectsOpsHtml, /data-ops-nav-group="status" data-ops-nav-expanded="false" data-ops-nav-has-active-child="false" data-ops-nav-locked="false"/);
  assert.match(projectsOpsHtml, /id="ops-nav-panel-status" aria-hidden="true"/);
  assert.match(projectsOpsHtml, /class="ops-nav-subitem active" aria-current="page" href="\/\?section=projects">[\s\S]*Tutte/);
  assert.doesNotMatch(projectsOpsHtml, /class="ops-nav-subitem active [^"]*" aria-current="page" data-status-category-card=/);
  assert.match(projectsOpsHtml, /href="\/\?section=projects&amp;project=node-demo"/);
  assert.match(projectsOpsHtml, /ops-nav-subdot good/);
  assert.match(projectsOpsHtml, /ops-project-row/);
  assert.match(projectsOpsHtml, /ops-project-state-dot good/);
  assert.match(projectsOpsHtml, /Php Demo/);
  assert.match(projectsOpsHtml, /Node Demo/);
  assert.match(projectsOpsHtml, /data-project-row-link="\/\?section=projects&amp;project=node-demo"/);
  assert.match(projectsOpsHtml, /href="https:\/\/node-demo\.localhost\.com\/"/);
  assert.match(projectsOpsHtml, /target="_blank"/);
  assert.match(projectsOpsHtml, /rel="noopener noreferrer"/);
  assert.match(projectsOpsHtml, /data-fit-single-line/);
  assert.match(projectsOpsHtml, /node-demo\.localhost\.com/);
  assert.match(projectsOpsHtml, /PHP Apache/);
  assert.match(projectsOpsHtml, /Node\/Next/);
  assert.doesNotMatch(projectsOpsHtml, /ops-project-row-status/);
  assert.doesNotMatch(projectsOpsHtml, /<em class="ops-state[^"]*">Online<\/em>/);
  assert.doesNotMatch(projectsOpsHtml, /0\.100%|3\.500%/);
  assert.doesNotMatch(projectsOpsHtml, /node-demo \/ 2 DB/);
  assert.doesNotMatch(projectsOpsHtml, /Aggiungi applicazione/);
  assert.doesNotMatch(projectsOpsHtml, /Archivia applicazione/);
  assert.doesNotMatch(projectsOpsHtml, /ARCHIVE-PROJECT/);
  assert.doesNotMatch(projectsOpsHtml, /Descrizione breve/);
  assert.doesNotMatch(projectsOpsHtml, /db-password-should-not-leak/);
  assert.doesNotMatch(projectsOpsHtml, /Platform Documentation/);

  const projectDetailHtml = await getText(`${baseUrl}/?section=projects&project=node-demo`);
  assert.match(projectDetailHtml, /ops-project-detail-screen/);
  assert.match(projectDetailHtml, /<label class="ops-project-select">\s*<select name="restoreMode"[\s\S]*?<span class="ops-project-select-chevron"/);
  assert.doesNotMatch(projectDetailHtml, /ops-project-detail-back/);
  assert.doesNotMatch(projectDetailHtml, /Torna ad Applicazioni/);
  assert.match(projectDetailHtml, /<section class="ops-page" aria-label="Applicazioni">/);
  assert.doesNotMatch(projectDetailHtml, /<h1 id="control-page-title">Applicazioni<\/h1>/);
  assert.doesNotMatch(projectDetailHtml, /Elenco applicazioni con host, runtime e dettaglio operativo/);
  assert.match(projectDetailHtml, /data-ops-nav-group="projects" data-ops-nav-expanded="true"/);
  assert.match(projectDetailHtml, /id="ops-nav-panel-projects" aria-hidden="false"/);
  assert.match(projectDetailHtml, /class="ops-nav-subitem active" aria-current="page" href="\/\?section=projects&amp;project=node-demo"/);
  assert.doesNotMatch(projectDetailHtml, /class="ops-nav-subitem active [^"]*" aria-current="page" data-status-category-card=/);
  assert.doesNotMatch(projectDetailHtml, /class="ops-nav-main[^"]*"[^>]*aria-current="page"/);
  assert.match(projectDetailHtml, /Node Demo/);
  assert.match(projectDetailHtml, /node-demo\.localhost\.com/);
  assert.match(projectDetailHtml, /Node\/Next/);
  assert.match(projectDetailHtml, /File manager/);
  assert.match(projectDetailHtml, /<h3>Database<\/h3>/);
  assert.match(projectDetailHtml, /Backup/);
  assert.ok(projectDetailHtml.indexOf('id="project-file-manager"') < projectDetailHtml.indexOf('id="project-backups"'));
  assert.ok(projectDetailHtml.indexOf('id="project-backups"') < projectDetailHtml.indexOf('id="project-databases"'));
  assert.match(projectDetailHtml, /ops-project-backup-list/);
  assert.match(projectDetailHtml, /4 risorse/);
  assert.match(projectDetailHtml, /name="backupMode" value="all"/);
  assert.doesNotMatch(projectDetailHtml, /Sorgenti \+ database/);
  assert.doesNotMatch(projectDetailHtml, /ops-project-backup-fixed-scope/);
  assert.match(projectDetailHtml, /name="backupRef"/);
  assert.match(projectDetailHtml, /name="restoreMode"/);
  assert.match(projectDetailHtml, /Tutto/);
  assert.match(projectDetailHtml, /Solo database/);
  assert.match(projectDetailHtml, /Solo sorgenti/);
  assert.match(projectDetailHtml, /Backup da ripristinare/);
  assert.match(projectDetailHtml, /Avvia restore drill/);
  assert.doesNotMatch(projectDetailHtml, />Ripristina backup</);
  assert.match(projectDetailHtml, /Avvia backup/);
  assert.ok(projectDetailHtml.indexOf("Avvia backup") < projectDetailHtml.indexOf('class="ops-project-backup-list"'));
  assert.match(projectDetailHtml, /ops-project-backup-head-form/);
  assert.doesNotMatch(projectDetailHtml, /Backup DB/);
  assert.match(projectDetailHtml, /name="returnTo" value="project-detail"/);
  assert.doesNotMatch(projectDetailHtml, /Apri backup di Node Demo/);
  assert.doesNotMatch(projectDetailHtml, /href="\/\?section=backups&amp;backupProject=node-demo"/);
  assert.match(projectDetailHtml, /Risorse utilizzate/);
  assert.doesNotMatch(projectDetailHtml, /Limiti<\/span>/);
  assert.doesNotMatch(projectDetailHtml, /Misurato da<\/span>/);
  assert.match(projectDetailHtml, /data-file-manager/);
  assert.match(projectDetailHtml, /data-file-search/);
  assert.match(projectDetailHtml, /placeholder="Cerca"/);
  assert.match(projectDetailHtml, /ops-file-commandbar[\s\S]*data-file-search[\s\S]*data-file-refresh-action/);
  assert.doesNotMatch(projectDetailHtml, /<span>Node Demo \/ \.<\/span>/);
  assert.match(projectDetailHtml, /data-file-manager-refresh-url="\/\?section=projects&amp;project=node-demo"/);
  assert.doesNotMatch(projectDetailHtml, /data-file-refresh-ms/);
  assert.match(projectDetailHtml, /data-file-refresh-action/);
  assert.match(projectDetailHtml, /ops-file-grid/);
  assert.match(projectDetailHtml, /role="listbox"/);
  assert.match(projectDetailHtml, /data-file-context-menu/);
  assert.match(projectDetailHtml, /data-file-menu-action="open"/);
  assert.match(projectDetailHtml, /data-file-menu-action="copy-path"/);
  assert.doesNotMatch(projectDetailHtml, /data-file-menu-action="details"/);
  assert.match(projectDetailHtml, /Aggiorna file manager/);
  assert.doesNotMatch(projectDetailHtml, /data-file-inspector/);
  assert.match(projectDetailHtml, /package\.json/);
  assert.match(projectDetailHtml, /src/);
  assert.match(projectDetailHtml, /node_demo_external/);
  assert.match(projectDetailHtml, /\d{2}\/\d{2}\/\d{4}, \d{2}:\d{2}:\d{2} (?:CET|CEST)/);
  assert.match(projectDetailHtml, /data-file-type="directory"/);
  assert.match(projectDetailHtml, /data-file-open-url="\/\?section=projects&amp;project=node-demo&amp;path=src"/);
  assert.match(projectDetailHtml, /href="\/\?section=projects&project=node-demo&path=src"/);
  assert.doesNotMatch(projectDetailHtml, /ops-project-file-table/);
  assert.doesNotMatch(projectDetailHtml, /href="\/\?section=files&project=node-demo"/);
  assert.match(projectDetailHtml, /href="\/actions\/phpmyadmin-login\?databaseId=legacy-mariadb-node-demo-external&amp;confirm=OPEN-PHPMYADMIN%3Alegacy-mariadb-node-demo-external"/);
  assert.match(projectDetailHtml, /href="\/actions\/phppgadmin-login\?databaseId=legacy-postgres-node-demo-external&amp;confirm=OPEN-PHPPGADMIN%3Alegacy-postgres-node-demo-external"/);
  assert.match(projectDetailHtml, /ops-project-database-list/);
  assert.match(projectDetailHtml, /Nome DB: node_demo_external \/ mariadb \/ utente:/);
  assert.doesNotMatch(projectDetailHtml, /aria-label="Stato database"/);
  assert.doesNotMatch(projectDetailHtml, /name="status"/);
  assert.doesNotMatch(projectDetailHtml, />declared<\/option>/);
  assert.match(projectDetailHtml, /Valore non mostrato/);
  assert.match(projectDetailHtml, /name="action" value="credential"/);
  assert.match(projectDetailHtml, /type="password" name="password" value="" placeholder="Nuova password"/);
  assert.doesNotMatch(projectDetailHtml, /name="credentialRef"/);
  assert.doesNotMatch(projectDetailHtml, /Riferimento secret password database/);
  assert.match(projectDetailHtml, /ROTATE-DATABASE-CREDENTIAL%3A|ROTATE-DATABASE-CREDENTIAL:/);
  assert.match(projectDetailHtml, /name="action" value="delete"/);
  assert.match(projectDetailHtml, /REQUEST-DATABASE-DELETE:/);
  assert.match(projectDetailHtml, /Richiedi eliminazione/);
  assert.doesNotMatch(projectDetailHtml, /name="openAfterCreate"/);
  assert.match(projectDetailHtml, /type="password" name="password" value="" placeholder="Password"/);
  assert.match(projectDetailHtml, /name="password" value="" placeholder="Password"[^>]*required/);
  assert.match(projectDetailHtml, /Crea DB/);
  assert.match(projectDetailHtml, /target="_blank"/);
  assert.match(projectDetailHtml, /rel="noopener noreferrer"/);
  assert.doesNotMatch(projectDetailHtml, /href="\/\?section=databases#app-node-demo"/);
  assert.doesNotMatch(projectDetailHtml, /href="\/\?section=databases#database-/);
  assert.doesNotMatch(projectDetailHtml, /db-password-should-not-leak/);
  assert.doesNotMatch(projectDetailHtml, /Platform Documentation/);
  const projectDetailSubpathHtml = await getText(`${baseUrl}/?section=projects&project=node-demo&path=src`);
  assert.match(projectDetailSubpathHtml, /File manager/);
  assert.match(projectDetailSubpathHtml, /index\.js/);
  assert.match(projectDetailSubpathHtml, /href="\/\?section=projects&project=node-demo"/);
  assert.doesNotMatch(projectDetailSubpathHtml, /href="\/\?section=files&project=node-demo"/);

  const networkApi = await getJson(`${baseUrl}/control/network`);
  assert.equal(networkApi.guardrails.readOnly, true);
  assert.equal(networkApi.guardrails.routeTestsArePlans, true);
  assert.equal(networkApi.providerTouched, false);
  assert.equal(networkApi.networkProbeExecuted, false);
  assert.equal(networkApi.productionEvidence, false);
  assert.equal(networkApi.routers.some((router) => router.id === "enterprise-portal" && router.tls === true && router.sampleHost === "portal.localhost.com" && router.middlewares.includes("enterprise-rate-limit@file")), true);
  assert.equal(networkApi.routers.some((router) => router.id === "enterprise-docs" && router.tls === true && router.sampleHost === "docs.localhost.com" && router.middlewares.includes("enterprise-rate-limit@file")), true);
  assert.equal(networkApi.routers.some((router) => router.id === "enterprise-backend"), false);
  assert.equal(networkApi.routers.some((router) => router.id === "local-projects"), false);
  assert.equal(networkApi.middlewares.some((middleware) => middleware.id === "enterprise-rate-limit" && middleware.type === "rateLimit" && /average 120/.test(middleware.summary)), true);
  assert.equal(networkApi.exposedPorts.some((port) => port.hostPort === "80" && port.containerPort === "80" && port.loopbackOnly === true && port.publicExposure === false), true);
  assert.equal(networkApi.exposedPorts.some((port) => port.hostPort === "443" && port.containerPort === "443" && port.loopbackOnly === true && port.publicExposure === false), true);
  assert.equal(networkApi.tls.status, "configured");
  assert.equal(networkApi.routeTests.some((testPlan) => testPlan.routerId === "enterprise-portal" && testPlan.url === "https://portal.localhost.com/" && testPlan.networkProbeExecuted === false), true);

  const advancedNetworkApi = await getJson(`${baseUrl}/control/advanced/network`);
  assert.equal(advancedNetworkApi.data.routers.some((router) => router.id === "enterprise-portal"), true);
  assert.equal(advancedNetworkApi.data.routers.some((router) => router.id === "enterprise-backend"), false);
  assert.equal(advancedNetworkApi.data.routeTests.some((testPlan) => testPlan.productionEvidence === false), true);
  assert.equal(advancedNetworkApi.data.originLockStatus, "not-required-local-loopback");

  const filesOpsHtml = await getText(`${baseUrl}/?section=files&project=node-demo`);
  assert.match(filesOpsHtml, /File applicazione/);
  assert.match(filesOpsHtml, /Elenco in sola lettura/);
  assert.match(filesOpsHtml, /package\.json|server\.mjs|index/);

  const monitoringApi = await getJson(`${baseUrl}/control/monitoring`);
  assert.equal(monitoringApi.guardrails.readOnly, true);
  assert.equal(monitoringApi.guardrails.noPrometheusQueryFromPanel, true);
  assert.equal(monitoringApi.guardrails.noLokiQueryFromPanel, true);
  assert.equal(monitoringApi.liveQueryExecuted, false);
  assert.equal(monitoringApi.productionEvidence, false);
  assert.equal(monitoringApi.scrapeJobs.some((job) => job.jobName === "platform-alert-dispatcher" && job.targets.includes("platform-alert-dispatcher:3000")), true);
  assert.equal(monitoringApi.scrapeJobs.some((job) => job.jobName === "node-exporter" && job.category === "host"), true);
  assert.equal(monitoringApi.scrapeJobs.some((job) => job.jobName === "cadvisor" && job.category === "container"), true);
  assert.equal(monitoringApi.datasources.some((datasource) => datasource.name === "Prometheus" && datasource.url === "http://prometheus:9090"), true);
  assert.equal(monitoringApi.datasources.some((datasource) => datasource.name === "Loki" && datasource.url === "http://loki:3100"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "Platform container logs" && panel.signal === "platform-errors"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "Alert delivery outcomes" && panel.signal === "alert-delivery"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "WAF events" && panel.signal === "waf-events"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "Auth failures" && panel.signal === "auth-failures"), true);
  assert.deepEqual(monitoringApi.signals.filter((signal) => signal.coverage !== "configured" || signal.liveQueryExecuted !== false), []);
  assert.equal(monitoringApi.alertmanager.credentialFileConfigured, true);
  assert.equal(monitoringApi.alertmanager.secretValueExposed, false);
  assert.equal(monitoringApi.loki.retentionPeriod, "168h");

  const advancedMonitoringApi = await getJson(`${baseUrl}/control/advanced/monitoring`);
  assert.equal(advancedMonitoringApi.data.signals.some((signal) => signal.id === "error-rate"), true);
  assert.equal(advancedMonitoringApi.data.prometheus.liveQueryExecuted, false);
  assert.equal(advancedMonitoringApi.productionEvidence, false);

  const databasesOpsHtml = await getText(`${baseUrl}/?section=databases&project=node-demo`);
  assert.match(databasesOpsHtml, /Database per applicazione/);
  assert.match(databasesOpsHtml, /Aggiungi metadata database/);
  assert.match(databasesOpsHtml, /Credenziali/);
  assert.match(databasesOpsHtml, /Node Demo/);
  assert.match(databasesOpsHtml, /node_demo_external/);
  assert.match(databasesOpsHtml, /phpmyadmin-login/);
  assert.match(databasesOpsHtml, /OPEN-PHPMYADMIN%3Alegacy-mariadb-node-demo-external/);
  assert.doesNotMatch(databasesOpsHtml, /id="app-php-demo"/);
  assert.doesNotMatch(databasesOpsHtml, /Nessun database collegato/);
  assert.doesNotMatch(databasesOpsHtml, /name="project"/);
  const activityOpsHtml = await getText(`${baseUrl}/?section=activity`);
  assert.match(activityOpsHtml, /Stato/);
  assert.match(activityOpsHtml, /Sezioni/);
  assert.match(activityOpsHtml, /data-status-section-detail="go-live"/);
  assert.doesNotMatch(activityOpsHtml, /Errori, avvisi e problemi/);
  assert.doesNotMatch(activityOpsHtml, /section=activity/);
  const resourcesOpsApi = await getJson(`${baseUrl}/control/resources/summary`);
  assert.equal(resourcesOpsApi.cards.applications.status, 2);
  assert.equal(resourcesOpsApi.containerMetricsAvailable, true);
  assert.match(resourcesOpsApi.source, /docker-stats-file/);
  assert.equal(resourcesOpsApi.rows.some((row) => row.applicationId === "php-demo" && row.cpu.includes("0.000%")), true);
  assert.equal(resourcesOpsApi.rows.some((row) => row.applicationId === "node-demo" && row.cpu.includes("3.500%")), true);
  const nodeRuntimeLimits = resourcesOpsApi.projectUsage.find((item) => item.projectId === "node-demo").runtimeLimits;
  assert.deepEqual(nodeRuntimeLimits, [{
    container: "node-demo",
    cpuLimitCores: 2,
    memoryLimitBytes: 536870912,
    memoryReservationBytes: 268435456,
    pidsLimit: 256,
  }]);
  const freshDockerStats = readFileSync(dockerStatsFile, "utf8");
  const staleDockerStats = JSON.parse(freshDockerStats);
  staleDockerStats.capturedAt = "2020-01-01T00:00:00.000Z";
  staleDockerStats.capturedAtEpoch = 1577836800;
  writeFileSync(dockerStatsFile, `${JSON.stringify(staleDockerStats, null, 2)}\n`);
  const staleResourcesOpsApi = await getJson(`${baseUrl}/control/resources/summary`);
  assert.equal(staleResourcesOpsApi.containerMetricsAvailable, false);
  assert.equal(staleResourcesOpsApi.rows.some((row) => row.cpu.includes("3.500%")), false);
  const futureDockerStats = JSON.parse(freshDockerStats);
  futureDockerStats.capturedAtEpoch = Math.floor(Date.now() / 1000) + 3600;
  futureDockerStats.capturedAt = new Date(futureDockerStats.capturedAtEpoch * 1000).toISOString();
  writeFileSync(dockerStatsFile, `${JSON.stringify(futureDockerStats, null, 2)}\n`);
  const futureResourcesOpsApi = await getJson(`${baseUrl}/control/resources/summary`);
  assert.equal(futureResourcesOpsApi.containerMetricsAvailable, false);
  writeFileSync(dockerStatsFile, freshDockerStats);

  const overview = await getJson(`${baseUrl}/control/overview`);
  assert.equal(overview.title, "Admin Control Center");
  assert.equal(overview.environment, "local");
  assert.equal(overview.modeEvidence, "local evidence only");
  assert.equal(overview.projects.total, 2);
  assert.equal(overview.projects.active, 2);
  assert.equal(overview.subdomains.total, 2);
  assert.equal(overview.subdomains.active, 2);
  assert.equal(overview.network.routers > 0, true);
  assert.equal(overview.network.middlewares > 0, true);
  assert.equal(overview.network.routeTests > 0, true);
  assert.equal(overview.monitoring.scrapeJobs > 0, true);
  assert.equal(overview.monitoring.dashboardPanels > 0, true);
  assert.equal(overview.monitoring.alertRules > 0, true);
  assert.equal(overview.readiness.productionReady, false);
  assert.equal(overview.readiness.pendingLiveProof > 0, true);
  assert.notEqual(overview.modeEvidence, "production evidence");

  const advancedApi = await getJson(`${baseUrl}/control/advanced`);
  assert.equal(advancedApi.dryRunDefault, true);
  assert.equal(advancedApi.liveProviderTouched, false);
  assert.equal(advancedApi.productionEvidence, false);
  assert.equal(advancedApi.sections.some((section) => section.id === "cloudflare" && section.endpoint === "/control/advanced/cloudflare"), true);
  assert.equal(advancedApi.sections.some((section) => section.id === "release-evidence"), true);
  assert.equal(advancedApi.sections.some((section) => section.id === "readiness" && section.endpoint === "/control/advanced/readiness"), true);

  const advancedCloudflare = await getJson(`${baseUrl}/control/advanced/cloudflare`);
  assert.equal(advancedCloudflare.label, "Cloudflare");
  assert.equal(advancedCloudflare.dryRunDefault, true);
  assert.equal(advancedCloudflare.providerTouched, false);
  assert.equal(advancedCloudflare.productionEvidence, false);
  assert.equal(advancedCloudflare.adapters.some((adapter) => adapter.id === "cloudflare" && adapter.name === "CloudflareAdapter"), true);
  assert.match(advancedCloudflare.data.apply, /blocked without explicit adapter/);
  assert.match(advancedCloudflare.data.verifyRemote, /required before production evidence/);
  assert.doesNotMatch(JSON.stringify(advancedCloudflare), /cloudflareToken|CLOUDFLARE_API_TOKEN|super-secret-token-should-not-leak/);

  const advancedReleaseApi = await getJson(`${baseUrl}/control/advanced/release-evidence`);
  assert.equal(advancedReleaseApi.label, "Release Evidence");
  assert.equal(advancedReleaseApi.data.requirements.includes("SBOM"), true);
  assert.equal(advancedReleaseApi.data.requirements.includes("rollback validation"), true);
  assert.equal(advancedReleaseApi.productionEvidence, false);

  const readiness = await getJson(`${baseUrl}/control/readiness`);
  assert.equal(readiness.title, "Admin Control Center Readiness Matrix");
  assert.equal(readiness.dryRunDefault, true);
  assert.equal(readiness.providerTouched, false);
  assert.equal(readiness.liveProviderTouched, false);
  assert.equal(readiness.dockerTouched, false);
  assert.equal(readiness.productionEvidence, false);
  assert.equal(readiness.localEvidenceIsProductionEvidence, false);
  assert.equal(readiness.controlCenter.checks.some((check) => check.id === "control-center-local-ui" && check.status === "passed"), true);
  assert.equal(readiness.controlCenter.checks.some((check) => check.id === "safe-adapter-boundary" && check.status === "plan-only"), true);
  assert.equal(readiness.manifests.productionReadiness.loaded, true);
  assert.equal(readiness.manifests.productionReadiness.requirementCount, 19);
  assert.equal(readiness.manifests.productionReadiness.requirements.some((item) => item.id === "tls-https-production-ready" && item.status === "pending-live-proof"), true);
  assert.equal(readiness.manifests.enterprise.loaded, true);
  assert.equal(readiness.summary.needsWork, 0);
  assert.equal(readiness.summary.localModeReady, true);
  assert.equal(readiness.summary.productionReady, false);
  assert.equal(readiness.summary.pendingLiveProof > 0, true);
  assert.equal(readiness.productionBlockers.some((item) => item.id === "production-live-proof"), true);
  assert.doesNotMatch(JSON.stringify(readiness), /CLOUDFLARE_API_TOKEN|super-secret-token-should-not-leak/);

  const statusApi = await getJson(`${baseUrl}/control/status`);
  assert.equal(statusApi.statusRun, null);
  assert.equal(statusApi.statusCatalog.length > 5, true);
  assert.equal(new Set(statusApi.statusCatalog.map((check) => check.id)).size, statusApi.statusCatalog.length);
  assert.equal(statusApi.statusCatalog.every((check) => ["probe", "evidence-validation", "external-required"].includes(check.executionMode)), true);
  assert.doesNotMatch(JSON.stringify(statusApi.statusCatalog), /snapshot/);
  assert.match(statusApi.goNoGo.status, /^(unknown|go|no-go)$/);
  const versionedStatusApi = await getJson(`${baseUrl}/control/v1/status`);
  assert.deepEqual(versionedStatusApi, statusApi);
  const statusRunResponse = await fetch(`${baseUrl}/actions/status-check`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: "",
  });
  assert.equal(statusRunResponse.ok, true);
  const statusAfterRun = await getJson(`${baseUrl}/control/status`);
  assert.equal(statusAfterRun.statusRun.scope, "platform-infrastructure");
  assert.equal(statusAfterRun.statusRun.destructive, false);
  assert.equal(statusAfterRun.statusRun.providerTouched, false);
  assert.equal(statusAfterRun.statusRun.dockerTouched, false);
  assert.equal(statusAfterRun.statusRun.checks.some((check) => check.id === "control-center-health"), false);
  assert.equal(statusAfterRun.statusRun.checks.some((check) => check.id === "control-center-assets"), false);
  assert.equal(statusAfterRun.statusRun.checks.some((check) => check.id === "portal-through-waf"), true);
  assert.equal(statusAfterRun.statusRun.checks.every((check) => ["probe", "evidence-validation", "external-required"].includes(check.executionMode)), true);
  assert.equal(statusAfterRun.statusRun.checks.length, statusAfterRun.statusCatalog.length);
  assert.deepEqual(
    new Set(statusAfterRun.statusRun.checks.map((check) => check.id)),
    new Set(statusAfterRun.statusCatalog.map((check) => check.id)),
  );
  assert.equal(statusAfterRun.statusRun.eventCount, (statusAfterRun.statusRun.checks.length * 2) + 2);
  assert.equal(statusAfterRun.statusEvents.length, statusAfterRun.statusRun.eventCount);
  assert.equal(statusAfterRun.statusEvents[0].type, "run-started");
  assert.equal(statusAfterRun.statusEvents.at(-1).type, "run-completed");
  assert.deepEqual(statusAfterRun.statusEvents.map((event) => event.sequence), statusAfterRun.statusEvents.map((_, index) => index + 1));
  const statusEventsApi = await getJson(`${baseUrl}/control/status/events?runId=${statusAfterRun.statusRun.id}`);
  assert.deepEqual(statusEventsApi.events, statusAfterRun.statusEvents);
  assert.doesNotMatch(JSON.stringify(statusAfterRun), /CLOUDFLARE_API_TOKEN|super-secret-token-should-not-leak/);
  const statusCategoryRunResponse = await fetch(`${baseUrl}/actions/status-check`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
    body: "scope=category&category=backup-dr",
  });
  assert.equal(statusCategoryRunResponse.ok, true);
  const statusCategoryRun = await statusCategoryRunResponse.json();
  assert.equal(statusCategoryRun.requestedScope, "category");
  assert.equal(statusCategoryRun.requestedCategory, "backup-dr");
  assert.equal(statusCategoryRun.destructive, false);
  assert.equal(statusCategoryRun.providerTouched, false);
  assert.equal(statusCategoryRun.checks.length > 0, true);
  assert.equal(statusCategoryRun.checks.every((check) => check.category === "backup-dr"), true);
  const streamedRunId = `status-ui-${Date.now().toString(36)}-fixture`;
  const statusEventStream = await fetch(`${baseUrl}/control/v1/status/events/stream?runId=${streamedRunId}`);
  assert.equal(statusEventStream.status, 200);
  assert.match(statusEventStream.headers.get("content-type") || "", /text\/event-stream/);
  const statusSingleRunResponse = await fetch(`${baseUrl}/actions/status-check`, {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" },
    body: `scope=check&category=domain-edge&checkId=cloudflare-access-admin&runId=${streamedRunId}`,
  });
  assert.equal(statusSingleRunResponse.ok, true);
  const statusSingleRun = await statusSingleRunResponse.json();
  assert.equal(statusSingleRun.requestedScope, "check");
  assert.equal(statusSingleRun.requestedCheckId, "cloudflare-access-admin");
  assert.equal(statusSingleRun.checks.length, 1);
  assert.equal(statusSingleRun.checks[0].id, "cloudflare-access-admin");
  assert.equal(statusSingleRun.checks[0].executionMode, "external-required");
  const statusEventText = await statusEventStream.text();
  assert.match(statusEventText, /event: status/);
  assert.match(statusEventText, /"type":"run-started"/);
  assert.match(statusEventText, /"type":"check-started"/);
  assert.match(statusEventText, /"type":"check-completed"/);
  assert.match(statusEventText, /"type":"run-completed"/);
  const statusHtmlAfterRun = await getText(`${baseUrl}/?section=status`);
  assert.match(statusHtmlAfterRun, /Ultimo run/);
  assert.match(statusHtmlAfterRun, /data-status-run-step-mark/);
  assert.match(statusHtmlAfterRun, /Go live e decisione/);
  assert.match(statusHtmlAfterRun, /statusCategory=github-release/);
  assert.match(statusHtmlAfterRun, /statusCategory=backup-dr/);
  assert.match(statusHtmlAfterRun, /<details class="ops-status-check-row/);
  assert.match(statusHtmlAfterRun, /ops-status-check-details/);
  assert.doesNotMatch(statusHtmlAfterRun, /<th>Controllo<\/th><th>Stato<\/th><th>Motivo<\/th><th>Cosa fare<\/th><th>Fonte<\/th>/);
  assert.match(statusHtmlAfterRun, /data-status-section-detail="go-live"/);
  assert.match(statusHtmlAfterRun, /name="scope" value="category"/);
  assert.match(statusHtmlAfterRun, /name="scope" value="check"/);
  assert.doesNotMatch(statusHtmlAfterRun, /full-restore-drill/);
  assert.doesNotMatch(statusHtmlAfterRun, /Control Center avviato/);
  assert.doesNotMatch(statusHtmlAfterRun, /Asset Portal serviti/);
  assert.doesNotMatch(statusHtmlAfterRun, /Control Center local UI contract/);
  assert.doesNotMatch(statusHtmlAfterRun, /Simple Mode operational MVP/);
  assert.doesNotMatch(statusHtmlAfterRun, /Advanced Mode enterprise sections/);

  const readinessHtml = await getText(`${baseUrl}/?mode=advanced&section=readiness`);
  assert.match(readinessHtml, /ops-shell/);
  assert.match(readinessHtml, /Esecuzione/);
  assert.doesNotMatch(readinessHtml, /Readiness Matrix/);

  const advancedIdentityApi = await getJson(`${baseUrl}/control/advanced/identity`);
  assert.equal(advancedIdentityApi.data.sessionPolicy, "PostgreSQL-backed; revocable; HttpOnly; Secure; SameSite=Lax");
  assert.equal(advancedIdentityApi.data.adminVerifierConfigured, false);
  assert.equal(advancedIdentityApi.data.adminUsers.some((user) => user.id === "local-admin" && user.credentialsExposed === false), true);
  assert.equal(advancedIdentityApi.data.roles.some((role) => role.id === "platform-owner" && role.permissions.includes("control:*")), true);
  assert.equal(advancedIdentityApi.data.sessions.some((session) => session.id === "control-center-session" && session.valueExposed === false), true);

  const advancedSecretsApi = await getJson(`${baseUrl}/control/advanced/secrets`);
  assert.equal(advancedSecretsApi.data.stores.every((store) => store.valueExposed === false), true);
  assert.doesNotMatch(JSON.stringify(advancedSecretsApi), /example-control-center-admin-login|cloudflareToken|CLOUDFLARE_API_TOKEN/);

  const adapters = await getJson(`${baseUrl}/control/adapters`);
  assert.equal(adapters.adapters.length >= 13, true);
  assert.equal(adapters.adapters.some((adapter) => adapter.name === "CloudflareAdapter"), true);
  assert.equal(adapters.adapters.some((adapter) => adapter.name === "DockerAdapter"), true);
  assert.equal(adapters.adapters.every((adapter) => adapter.dryRunDefault === true && adapter.liveProviderTouched === false && adapter.productionEvidence === false), true);
  assert.equal(adapters.adapters.every((adapter) => adapter.guardrails.clientCannotExecuteShell === true), true);

  const cloudflareAdapter = await getJson(`${baseUrl}/control/adapters/cloudflare`);
  assert.equal(cloudflareAdapter.name, "CloudflareAdapter");
  assert.equal(cloudflareAdapter.capabilities.includes("verify remote"), true);
  assert.equal(cloudflareAdapter.guardrails.applyRequiresStrongConfirmation, true);
  assert.equal(cloudflareAdapter.guardrails.sensitiveValuesExposed, false);

  const adapterPlan = await postJson(`${baseUrl}/control/adapters/cloudflare/plan`, {
    action: "dns-record",
    cloudflareToken: "adapter-secret-should-not-leak",
  });
  assert.equal(adapterPlan.status, 202);
  assert.equal(adapterPlan.body.type, "adapter.cloudflare.dns-record.plan");
  assert.equal(adapterPlan.body.dryRun, true);
  assert.equal(adapterPlan.body.details.liveProviderTouched, false);
  assert.equal(adapterPlan.body.details.productionEvidence, false);
  assert.match(adapterPlan.body.details.confirmationRequired, /ADAPTER-APPLY:cloudflare:dns-record/);
  assert.doesNotMatch(JSON.stringify(adapterPlan.body), /adapter-secret-should-not-leak/);

  const adapterVerify = await postJson(`${baseUrl}/control/adapters/go-no-go/verify`, {
    scope: "production",
  });
  assert.equal(adapterVerify.status, 202);
  assert.equal(adapterVerify.body.type, "adapter.go-no-go.verify.plan");
  assert.equal(adapterVerify.body.details.productionEvidence, false);
  assert.equal(adapterVerify.body.details.dockerTouched, false);

  const adapterApplyRejected = await postJson(`${baseUrl}/control/adapters/cloudflare/apply`, {
    action: "dns-record",
    confirm: "ADAPTER-APPLY:cloudflare:dns-record",
  });
  assert.equal(adapterApplyRejected.status, 409);
  assert.match(adapterApplyRejected.body.message, /disabled for CloudflareAdapter/);

  const projects = await getJson(`${baseUrl}/control/projects`);
  assert.deepEqual(projects.projects.map((project) => [project.slug, project.type]), [
    ["php-demo", "PHP Apache"],
    ["node-demo", "Node/Next"],
  ]);

  const duplicateProject = await postJson(`${baseUrl}/control/projects`, {
    slug: "node-demo",
  });
  assert.equal(duplicateProject.status, 422);
  assert.match(duplicateProject.body.message, /already exists/);

  const projectPlan = await postJson(`${baseUrl}/control/projects`, {
    displayName: "Client Portal",
    description: "Area clienti",
    runtime: "static",
    secret: "project-secret-should-not-leak",
  });
  assert.equal(projectPlan.status, 202);
  assert.equal(projectPlan.body.type, "project.create");
  assert.equal(projectPlan.body.dryRun, true);
  assert.equal(projectPlan.body.details.confirmationRequired, "CREATE-PROJECT");
  assert.equal(projectPlan.body.details.filesystemTouched, false);
  assert.equal(projectPlan.body.details.dockerTouched, false);
  assert.equal(projectPlan.body.details.databaseTouched, false);
  assert.equal(projectPlan.body.details.providerTouched, false);
  assert.equal(projectPlan.body.details.productionEvidence, false);
  assert.equal(projectPlan.body.details.projectId, "client-portal");
  assert.equal(projectPlan.body.details.host, "client-portal.localhost.com");
  assert.equal(projectPlan.body.details.type, "Static");
  assert.equal(projectPlan.body.details.description, "Area clienti");
  assert.doesNotMatch(JSON.stringify(projectPlan.body), /project-secret-should-not-leak/);

  const projectApply = await postJson(`${baseUrl}/control/projects`, {
    displayName: "Client Portal",
    description: "Area clienti",
    runtime: "static",
    confirm: "CREATE-PROJECT",
    secret: "project-secret-should-not-leak",
  });
  assert.equal(projectApply.status, 202);
  assert.equal(projectApply.body.type, "project.create.local");
  assert.equal(projectApply.body.project.slug, "client-portal");
  assert.equal(projectApply.body.project.type, "Static");
  assert.equal(projectApply.body.project.description, "Area clienti");
  assert.equal(projectApply.body.project.status, "declared");
  assert.equal(projectApply.body.project.enabled, false);
  assert.equal(projectApply.body.project.filesystemExists, false);
  assert.equal(projectApply.body.project.filesystemTouched, false);
  assert.equal(projectApply.body.project.dockerTouched, false);
  assert.equal(projectApply.body.project.databaseTouched, false);

  const declaredProject = await getJson(`${baseUrl}/control/projects/client-portal`);
  assert.equal(declaredProject.slug, "client-portal");
  assert.equal(declaredProject.status, "declared");
  assert.equal(declaredProject.filesystemExists, false);

  const declaredProjectEnableRejected = await postJson(`${baseUrl}/actions/toggle-project`, {
    slug: "client-portal",
    enabled: "1",
  });
  assert.equal(declaredProjectEnableRejected.status, 409);
  assert.match(declaredProjectEnableRejected.body.message, /source files/);

  const projectsAfterCreate = await getJson(`${baseUrl}/control/projects`);
  assert.equal(projectsAfterCreate.projects.some((project) => project.slug === "client-portal" && project.status === "declared"), true);
  assert.equal(existsSync(stateFile), true);
  const projectStateText = readFileSync(stateFile, "utf8");
  assert.doesNotMatch(projectStateText, /project-secret-should-not-leak/);
  assert.equal(JSON.parse(projectStateText).projects["client-portal"].declaredProject, true);

  const projectsHtmlAfterCreate = await getText(`${baseUrl}/?section=projects`);
  assert.match(projectsHtmlAfterCreate, /Client Portal/);
  assert.match(projectsHtmlAfterCreate, /ops-project-state-dot bad/);
  assert.doesNotMatch(projectsHtmlAfterCreate, /File mancanti/);
  assert.doesNotMatch(projectsHtmlAfterCreate, /Aggiungi applicazione/);
  assert.doesNotMatch(projectsHtmlAfterCreate, /Archivia applicazione/);
  const declaredProjectDetailHtml = await getText(`${baseUrl}/?section=projects&project=client-portal`);
  assert.match(declaredProjectDetailHtml, /Client Portal/);
  assert.match(declaredProjectDetailHtml, /File manager/);
  assert.match(declaredProjectDetailHtml, /File non disponibili/);
  const applicationPlan = await postJson(`${baseUrl}/control/applications`, {
    projectId: "node-demo",
    name: "events-worker",
    runtime: "worker",
    webspaceId: "node-demo",
    repositoryUrl: "https://github.com/example/events-worker",
    secret: "application-secret-should-not-leak",
  });
  assert.equal(applicationPlan.status, 202);
  assert.equal(applicationPlan.body.type, "application.create");
  assert.equal(applicationPlan.body.dryRun, true);
  assert.equal(applicationPlan.body.details.confirmationRequired, "CREATE-APPLICATION");
  assert.equal(applicationPlan.body.details.filesystemTouched, false);
  assert.equal(applicationPlan.body.details.dockerTouched, false);
  assert.equal(applicationPlan.body.details.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(applicationPlan.body), /application-secret-should-not-leak/);

  const applicationApply = await postJson(`${baseUrl}/control/applications`, {
    projectId: "node-demo",
    name: "events-worker",
    runtime: "worker",
    webspaceId: "node-demo",
    repositoryUrl: "https://github.com/example/events-worker",
    confirm: "CREATE-APPLICATION",
    secret: "application-secret-should-not-leak",
  });
  assert.equal(applicationApply.status, 202);
  assert.equal(applicationApply.body.type, "application.create.local");
  assert.equal(applicationApply.body.dryRun, false);
  assert.equal(applicationApply.body.application.id, "node-demo-events-worker");
  assert.equal(applicationApply.body.application.runtime, "worker");
  assert.equal(applicationApply.body.application.webspaceId, "node-demo");
  assert.equal(applicationApply.body.application.filesystemTouched, false);
  assert.equal(applicationApply.body.application.dockerTouched, false);

  const applications = await getJson(`${baseUrl}/control/applications`);
  const workerApp = applications.applications.find((app) => app.id === "node-demo-events-worker");
  assert.equal(workerApp.runtime, "worker");
  assert.equal(workerApp.status, "declared");
  assert.equal(workerApp.source, "control-center-state");
  assert.equal(existsSync(applicationsFile), true);
  const applicationsText = readFileSync(applicationsFile, "utf8");
  assert.doesNotMatch(applicationsText, /application-secret-should-not-leak/);
  assert.equal(JSON.parse(applicationsText)["node-demo-events-worker"].runtime, "worker");

  const startPlan = await postJson(`${baseUrl}/control/applications/node-demo-events-worker/start`, {
    secret: "lifecycle-secret-should-not-leak",
  });
  assert.equal(startPlan.status, 202);
  assert.equal(startPlan.body.type, "application.start");
  assert.equal(startPlan.body.dryRun, true);
  assert.equal(startPlan.body.details.confirmationRequired, "START-APPLICATION:node-demo-events-worker");
  assert.equal(startPlan.body.details.commandExecuted, false);
  assert.equal(startPlan.body.details.dockerTouched, false);
  assert.equal(startPlan.body.details.healthcheckNetworkTouched, false);
  assert.doesNotMatch(JSON.stringify(startPlan.body), /lifecycle-secret-should-not-leak/);

  const startApply = await postJson(`${baseUrl}/control/applications/node-demo-events-worker/start`, {
    confirm: "START-APPLICATION:node-demo-events-worker",
    secret: "lifecycle-secret-should-not-leak",
  });
  assert.equal(startApply.status, 202);
  assert.equal(startApply.body.type, "application.start.local");
  assert.equal(startApply.body.dryRun, false);
  assert.equal(startApply.body.application.status, "online");
  assert.equal(startApply.body.application.lastLifecycleAction, "start");
  assert.equal(startApply.body.application.dockerTouched, false);
  assert.equal(startApply.body.details.commandExecuted, false);
  assert.doesNotMatch(JSON.stringify(startApply.body), /lifecycle-secret-should-not-leak/);

  const healthApply = await postJson(`${baseUrl}/control/applications/node-demo-events-worker/healthcheck`, {
    confirm: "HEALTHCHECK-APPLICATION:node-demo-events-worker",
  });
  assert.equal(healthApply.status, 202);
  assert.equal(healthApply.body.type, "application.healthcheck.local");
  assert.equal(healthApply.body.application.healthStatus, "metadata-routable");
  assert.equal(healthApply.body.details.healthcheckNetworkTouched, false);

  const stopApply = await postJson(`${baseUrl}/control/applications/node-demo-events-worker/stop`, {
    confirm: "STOP-APPLICATION:node-demo-events-worker",
  });
  assert.equal(stopApply.status, 202);
  assert.equal(stopApply.body.type, "application.stop.local");
  assert.equal(stopApply.body.application.status, "offline");
  assert.equal(stopApply.body.application.healthStatus, "metadata-disabled");

  const restartApply = await postJson(`${baseUrl}/control/applications/node-demo-events-worker/restart`, {
    confirm: "RESTART-APPLICATION:node-demo-events-worker",
  });
  assert.equal(restartApply.status, 202);
  assert.equal(restartApply.body.type, "application.restart.local");
  assert.equal(restartApply.body.application.status, "online");
  assert.equal(restartApply.body.application.lastLifecycleAction, "restart");
  assert.equal(restartApply.body.details.commandExecuted, false);

  const applicationsAfterLifecycle = await getJson(`${baseUrl}/control/applications`);
  const workerAppAfterLifecycle = applicationsAfterLifecycle.applications.find((app) => app.id === "node-demo-events-worker");
  assert.equal(workerAppAfterLifecycle.status, "online");
  assert.equal(workerAppAfterLifecycle.lifecycleMode, "local-metadata-only");
  assert.equal(JSON.parse(readFileSync(applicationsFile, "utf8"))["node-demo-events-worker"].lastLifecycleAction, "restart");
  assert.doesNotMatch(readFileSync(applicationsFile, "utf8"), /lifecycle-secret-should-not-leak/);

  const applicationsAfterCreate = await getJson(`${baseUrl}/control/applications`);
  assert.equal(applicationsAfterCreate.applications.some((app) => app.id === "node-demo-events-worker" && app.status === "online"), true);
  assert.doesNotMatch(JSON.stringify(applicationsAfterCreate), /application-secret-should-not-leak/);

  const workerInventoryInitial = await getJson(`${baseUrl}/control/workers-jobs`);
  assert.equal(workerInventoryInitial.workers.some((worker) => worker.id === "enterprise-backup-scheduler"), true);
  assert.equal(workerInventoryInitial.workers.some((worker) => worker.id === "node-demo-events-worker"), true);
  assert.equal(workerInventoryInitial.queues.some((queue) => queue.id === "maintenance"), true);
  assert.equal(workerInventoryInitial.schedules.some((schedule) => schedule.id === "backup-scheduler" && schedule.containerizedCron === true), true);

  const workerInvalid = await postJson(`${baseUrl}/control/workers-jobs/queues`, {
    projectId: "node-demo",
    name: "../bad",
  });
  assert.equal(workerInvalid.status, 422);
  assert.match(workerInvalid.body.message, /Invalid queue/);

  const workerPlan = await postJson(`${baseUrl}/control/workers-jobs/workers`, {
    projectId: "node-demo",
    name: "events-processor",
    service: "worker-events",
    status: "configured",
    queueName: "events",
    concurrency: 2,
    maxAttempts: 5,
    secret: "worker-secret-should-not-leak",
  });
  assert.equal(workerPlan.status, 202);
  assert.equal(workerPlan.body.type, "worker.declare");
  assert.equal(workerPlan.body.dryRun, true);
  assert.equal(workerPlan.body.details.confirmationRequired, "DECLARE-WORKER");
  assert.equal(workerPlan.body.details.dockerTouched, false);
  assert.equal(workerPlan.body.details.commandExecuted, false);
  assert.doesNotMatch(JSON.stringify(workerPlan.body), /worker-secret-should-not-leak/);

  const workerApply = await postJson(`${baseUrl}/control/workers-jobs/workers`, {
    projectId: "node-demo",
    name: "events-processor",
    service: "worker-events",
    status: "configured",
    queueName: "events",
    concurrency: 2,
    maxAttempts: 5,
    confirm: "DECLARE-WORKER",
    secret: "worker-secret-should-not-leak",
  });
  assert.equal(workerApply.status, 202);
  assert.equal(workerApply.body.type, "worker.declare.local");
  assert.equal(workerApply.body.worker.id, "node-demo-events-processor");
  assert.equal(workerApply.body.worker.dockerTouched, false);
  assert.equal(workerApply.body.worker.commandExecuted, false);

  const queueApply = await postJson(`${baseUrl}/control/workers-jobs/queues`, {
    projectId: "node-demo",
    name: "events",
    backend: "nats",
    status: "configured",
    retryPolicy: "max-5-attempts",
    confirm: "DECLARE-QUEUE",
    secret: "worker-secret-should-not-leak",
  });
  assert.equal(queueApply.status, 202);
  assert.equal(queueApply.body.type, "worker.queue.local");
  assert.equal(queueApply.body.queue.id, "node-demo-events");
  assert.equal(queueApply.body.queue.brokerTouched, false);

  const jobApply = await postJson(`${baseUrl}/control/workers-jobs/jobs`, {
    projectId: "node-demo",
    queueId: "node-demo-events",
    workerId: "node-demo-events-processor",
    jobName: "sync-events",
    status: "failed",
    attempts: 2,
    maxAttempts: 5,
    lastError: "request failed token=worker-secret-should-not-leak",
    confirm: "RECORD-JOB",
  });
  assert.equal(jobApply.status, 202);
  assert.equal(jobApply.body.type, "worker.job.record.local");
  assert.equal(jobApply.body.job.id, "node-demo-node-demo-events-sync-events");
  assert.equal(jobApply.body.job.handlerExecuted, false);
  assert.equal(jobApply.body.job.dockerTouched, false);
  assert.doesNotMatch(JSON.stringify(jobApply.body), /worker-secret-should-not-leak/);

  const retryApply = await postJson(`${baseUrl}/control/workers-jobs/jobs/node-demo-node-demo-events-sync-events/retry`, {
    retryAfterSeconds: 120,
    confirm: "PLAN-JOB-RETRY",
    secret: "worker-secret-should-not-leak",
  });
  assert.equal(retryApply.status, 202);
  assert.equal(retryApply.body.type, "worker.job.retry.local");
  assert.equal(retryApply.body.job.status, "retry-planned");
  assert.equal(retryApply.body.details.handlerExecuted, false);
  assert.equal(retryApply.body.details.brokerTouched, false);

  const badSchedule = await postJson(`${baseUrl}/control/workers-jobs/schedules`, {
    projectId: "node-demo",
    workerId: "node-demo-events-processor",
    queueId: "node-demo-events",
    name: "bad schedule",
    cronExpression: "* * *",
  });
  assert.equal(badSchedule.status, 422);
  assert.match(badSchedule.body.message, /Cron expression/);

  const scheduleApply = await postJson(`${baseUrl}/control/workers-jobs/schedules`, {
    projectId: "node-demo",
    workerId: "node-demo-events-processor",
    queueId: "node-demo-events",
    name: "nightly-events-sync",
    cronExpression: "15 3 * * *",
    status: "enabled",
    confirm: "DECLARE-SCHEDULE",
  });
  assert.equal(scheduleApply.status, 202);
  assert.equal(scheduleApply.body.type, "worker.schedule.local");
  assert.equal(scheduleApply.body.schedule.id, "node-demo-nightly-events-sync");
  assert.equal(scheduleApply.body.schedule.containerizedCron, true);
  assert.equal(scheduleApply.body.schedule.dockerTouched, false);
  assert.equal(scheduleApply.body.schedule.crontabTouched, false);

  const schedulePause = await postJson(`${baseUrl}/control/workers-jobs/schedules/node-demo-nightly-events-sync/status`, {
    status: "paused",
    confirm: "UPDATE-SCHEDULE",
  });
  assert.equal(schedulePause.status, 202);
  assert.equal(schedulePause.body.type, "worker.schedule.status.local");
  assert.equal(schedulePause.body.schedule.status, "paused");
  assert.equal(schedulePause.body.details.crontabTouched, false);

  const workerInventory = await getJson(`${baseUrl}/control/workers-jobs`);
  assert.equal(workerInventory.workers.some((worker) => worker.id === "node-demo-events-processor" && worker.commandExecuted === false), true);
  assert.equal(workerInventory.queues.some((queue) => queue.id === "node-demo-events" && queue.brokerTouched === false), true);
  assert.equal(workerInventory.jobs.some((job) => job.id === "node-demo-node-demo-events-sync-events" && job.status === "retry-planned"), true);
  assert.equal(workerInventory.schedules.some((schedule) => schedule.id === "node-demo-nightly-events-sync" && schedule.status === "paused"), true);
  assert.equal(existsSync(workerJobsFile), true);
  const workerJobsText = readFileSync(workerJobsFile, "utf8");
  assert.doesNotMatch(workerJobsText, /worker-secret-should-not-leak/);
  assert.equal(JSON.parse(workerJobsText).workers["node-demo-events-processor"].service, "worker-events");

  const advancedWorkersAfterApply = await getJson(`${baseUrl}/control/advanced/workers-jobs`);
  assert.equal(advancedWorkersAfterApply.data.queues.some((queue) => queue.id === "node-demo-events"), true);
  assert.equal(advancedWorkersAfterApply.data.jobs.some((job) => job.id === "node-demo-node-demo-events-sync-events"), true);
  assert.equal(advancedWorkersAfterApply.data.scheduler.some((schedule) => schedule.id === "node-demo-nightly-events-sync"), true);
  assert.equal(advancedWorkersAfterApply.productionEvidence, false);

  const workerLogsAfterApply = await getJson(`${baseUrl}/control/logs/summary`);
  assert.doesNotMatch(JSON.stringify(workerLogsAfterApply), /worker-secret-should-not-leak/);

  const projectsHtml = await getText(`${baseUrl}/?section=projects`);
  assert.doesNotMatch(projectsHtml, /ARCHIVE-PROJECT/);
  assert.doesNotMatch(projectsHtml, /Aggiungi/);
  assert.doesNotMatch(projectsHtml, /archivia/i);
  assert.doesNotMatch(projectsHtml, /DELETE-PROJECT:php-demo/);

  const updatePlan = await postJson(`${baseUrl}/control/projects/node-demo/update`, {
    displayName: "Node Demo Local",
  });
  assert.equal(updatePlan.status, 202);
  assert.equal(updatePlan.body.type, "project.update");
  assert.equal(updatePlan.body.dryRun, true);

  const updateApply = await postJson(`${baseUrl}/control/projects/node-demo/update`, {
    displayName: "Node Demo Local",
    confirm: "UPDATE-PROJECT",
  });
  assert.equal(updateApply.status, 202);
  assert.equal(updateApply.body.type, "project.update.local");
  assert.equal(updateApply.body.dryRun, false);

  const archivePlan = await postJson(`${baseUrl}/control/projects/php-demo/archive/plan`, {});
  assert.equal(archivePlan.status, 202);
  assert.equal(archivePlan.body.type, "project.archive");
  assert.equal(archivePlan.body.details.confirmationRequired, "ARCHIVE-PROJECT");

  const archiveRejected = await postJson(`${baseUrl}/control/projects/php-demo/archive/apply`, {
    confirm: "wrong",
  });
  assert.equal(archiveRejected.status, 409);

  const archiveApply = await postJson(`${baseUrl}/control/projects/php-demo/archive/apply`, {
    confirm: "ARCHIVE-PROJECT",
  });
  assert.equal(archiveApply.status, 202);
  assert.equal(archiveApply.body.type, "project.archive.local");
  assert.equal(archiveApply.body.details.filesystemTouched, false);

  const projectsAfterArchive = await getJson(`${baseUrl}/control/projects`);
  const archivedProject = projectsAfterArchive.projects.find((project) => project.slug === "php-demo");
  assert.equal(archivedProject.status, "archived");
  assert.equal(archivedProject.enabled, false);
  const overviewAfterArchive = await getJson(`${baseUrl}/control/overview`);
  assert.equal(overviewAfterArchive.projects.archived, 1);

  const deletePlan = await postJson(`${baseUrl}/control/projects/php-demo/delete/plan`, {});
  assert.equal(deletePlan.status, 202);
  assert.equal(deletePlan.body.type, "project.delete");
  assert.equal(deletePlan.body.details.confirmationRequired, "DELETE-PROJECT:php-demo");

  const deleteRejected = await postJson(`${baseUrl}/control/projects/php-demo/delete/apply`, {
    confirm: "DELETE-PROJECT",
  });
  assert.equal(deleteRejected.status, 409);

  const deleteApply = await postJson(`${baseUrl}/control/projects/php-demo/delete/apply`, {
    confirm: "DELETE-PROJECT:php-demo",
  });
  assert.equal(deleteApply.status, 202);
  assert.equal(deleteApply.body.type, "project.delete.local");
  assert.equal(deleteApply.body.details.filesystemTouched, false);
  assert.equal(deleteApply.body.details.databaseTouched, false);
  assert.equal(existsSync(path.join(projectsRoot, "php-demo", "public", "index.php")), true);

  const projectsAfterDelete = await getJson(`${baseUrl}/control/projects`);
  assert.equal(projectsAfterDelete.projects.some((project) => project.slug === "php-demo"), false);
  assert.equal(projectsAfterDelete.projects.some((project) => project.slug === "node-demo"), true);

  const prodLocalhostPlan = await postJson(`${baseUrl}/control/subdomains/plan`, {
    environment: "production",
    projectId: "node-demo",
    hostname: "bad.localhost.com",
  });
  assert.equal(prodLocalhostPlan.status, 422);
  assert.match(prodLocalhostPlan.body.message, /real domain/);

  const prodApplyWithoutConfirm = await postJson(`${baseUrl}/control/subdomains/apply`, {
    environment: "production",
    projectId: "node-demo",
    hostname: "site.example.com",
  });
  assert.equal(prodApplyWithoutConfirm.status, 409);
  assert.match(prodApplyWithoutConfirm.body.message, /APPLY-PRODUCTION/);

  const prodApplyDisabled = await postJson(`${baseUrl}/control/subdomains/apply`, {
    environment: "production",
    projectId: "node-demo",
    hostname: "site.example.com",
    confirm: "APPLY-PRODUCTION",
  });
  assert.equal(prodApplyDisabled.status, 409);
  assert.match(prodApplyDisabled.body.message, /disabled/);

  const domainsHtml = await getText(`${baseUrl}/?section=domains`);
  assert.match(domainsHtml, /ops-shell/);
  assert.doesNotMatch(domainsHtml, /Add domain/);
  assert.doesNotMatch(domainsHtml, /Provider connection/);

  const prodLocalhostDomain = await postJson(`${baseUrl}/control/domains`, {
    environment: "production",
    baseDomain: "localhost.com",
  });
  assert.equal(prodLocalhostDomain.status, 422);
  assert.match(prodLocalhostDomain.body.message, /real domain/);

  const domainPlan = await postJson(`${baseUrl}/control/domains`, {
    environment: "staging",
    baseDomain: "staging.example.com",
    visibility: "admin",
    providerConnectionId: "cloudflare",
    cloudflareToken: "domain-secret-should-not-leak",
  });
  assert.equal(domainPlan.status, 202);
  assert.equal(domainPlan.body.type, "domain.create");
  assert.equal(domainPlan.body.dryRun, true);
  assert.equal(domainPlan.body.details.confirmationRequired, "CREATE-DOMAIN");
  assert.equal(domainPlan.body.details.providerTouched, false);
  assert.equal(domainPlan.body.details.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(domainPlan.body), /domain-secret-should-not-leak/);

  const domainApply = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "create-domain",
    environment: "staging",
    baseDomain: "staging.example.com",
    visibility: "admin",
    providerConnectionId: "cloudflare",
    confirm: "CREATE-DOMAIN",
    cloudflareToken: "domain-secret-should-not-leak",
  });
  assert.equal(domainApply.status, 202);
  assert.equal(domainApply.body.type, "domain.create.local");
  assert.equal(domainApply.body.domain.baseDomain, "staging.example.com");
  assert.equal(domainApply.body.domain.providerTouched, false);
  assert.equal(domainApply.body.domain.productionEvidence, false);
  assert.equal(existsSync(domainsFile), true);
  const domainsText = readFileSync(domainsFile, "utf8");
  assert.doesNotMatch(domainsText, /domain-secret-should-not-leak/);
  assert.equal(JSON.parse(domainsText)["staging-staging-example-com"].baseDomain, "staging.example.com");

  const domainsAfterDomainApply = await getJson(`${baseUrl}/control/domains`);
  assert.equal(domainsAfterDomainApply.domains.some((domain) => domain.baseDomain === "staging.example.com"), true);

  const uiSubdomainApply = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "apply-local",
    projectId: "node-demo",
    hostname: "ui-catalog.localhost.com",
    visibility: "admin",
    protection: "passkey",
    secret: "subdomain-ui-secret-should-not-leak",
  });
  assert.equal(uiSubdomainApply.status, 202);
  assert.equal(uiSubdomainApply.body.type, "subdomain.apply.local");
  assert.equal(uiSubdomainApply.body.details.hostname, "ui-catalog.localhost.com");
  assert.equal(uiSubdomainApply.body.details.visibility, "admin");
  assert.equal(uiSubdomainApply.body.details.protection, "passkey");
  assert.doesNotMatch(JSON.stringify(uiSubdomainApply.body), /subdomain-ui-secret-should-not-leak/);

  const uiSubdomainVerify = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "verify",
    id: "ui-catalog-localhost-com",
  });
  assert.equal(uiSubdomainVerify.status, 202);
  assert.equal(uiSubdomainVerify.body.type, "subdomain.verify");

  const uiRemoveRejected = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "remove",
    id: "ui-catalog-localhost-com",
    confirm: "wrong",
  });
  assert.equal(uiRemoveRejected.status, 409);

  const uiRemoveApply = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "remove",
    id: "ui-catalog-localhost-com",
    confirm: "REMOVE-SUBDOMAIN",
  });
  assert.equal(uiRemoveApply.status, 202);
  assert.equal(uiRemoveApply.body.type, "subdomain.remove");

  const domainsAfterUiRemove = await getJson(`${baseUrl}/control/domains`);
  assert.equal(domainsAfterUiRemove.subdomains.some((item) => item.hostname === "ui-catalog.localhost.com"), false);

  const invalidWebspace = await postJson(`${baseUrl}/control/webspaces`, {
    projectId: "node-demo",
    basePath: "../secret",
  });
  assert.equal(invalidWebspace.status, 422);
  assert.match(invalidWebspace.body.message, /Invalid webspace path/);

  const webspacesApi = await getJson(`${baseUrl}/control/webspaces`);
  assert.equal(Array.isArray(webspacesApi.webspaces), true);

  const webspacePlan = await postJson(`${baseUrl}/control/webspaces`, {
    projectId: "node-demo",
    name: "media",
    quotaBytes: 4096,
    secret: "webspace-secret-should-not-leak",
  });
  assert.equal(webspacePlan.status, 202);
  assert.equal(webspacePlan.body.type, "webspace.create");
  assert.equal(webspacePlan.body.dryRun, true);
  assert.equal(webspacePlan.body.details.confirmationRequired, "CREATE-WEBSPACE");
  assert.equal(webspacePlan.body.details.filesystemTouched, false);
  assert.doesNotMatch(JSON.stringify(webspacePlan.body), /webspace-secret-should-not-leak/);

  const webspaceApply = await postJson(`${baseUrl}/control/webspaces`, {
    projectId: "node-demo",
    name: "media",
    quotaBytes: 4096,
    confirm: "CREATE-WEBSPACE",
    secret: "webspace-secret-should-not-leak",
  });
  assert.equal(webspaceApply.status, 202);
  assert.equal(webspaceApply.body.type, "webspace.create.local");
  assert.equal(webspaceApply.body.dryRun, false);
  assert.equal(webspaceApply.body.webspace.id, "node-demo-media");
  assert.deepEqual(webspaceApply.body.webspace.mounts, ["public", "private", "uploads", "backups", "config"]);
  assert.equal(webspaceApply.body.details.filesystemTouched, false);

  const quotaPlan = await postJson(`${baseUrl}/control/webspaces/node-demo-media/quota`, {
    quotaBytes: 8192,
  });
  assert.equal(quotaPlan.status, 202);
  assert.equal(quotaPlan.body.type, "webspace.quota");
  assert.equal(quotaPlan.body.details.confirmationRequired, "UPDATE-QUOTA");

  const quotaApply = await postJson(`${baseUrl}/control/webspaces/node-demo-media/quota`, {
    quotaBytes: 8192,
    confirm: "UPDATE-QUOTA",
  });
  assert.equal(quotaApply.status, 202);
  assert.equal(quotaApply.body.type, "webspace.quota.local");
  assert.equal(quotaApply.body.webspace.quotaBytes, 8192);

  const webspacesAfterApply = await getJson(`${baseUrl}/control/webspaces`);
  const mediaSpace = webspacesAfterApply.webspaces.find((space) => space.id === "node-demo-media");
  assert.equal(mediaSpace.quotaBytes, 8192);
  assert.equal(mediaSpace.basePath, "webspaces/node-demo/media");
  assert.equal(existsSync(webspacesFile), true);
  const webspaceStateText = readFileSync(webspacesFile, "utf8");
  assert.doesNotMatch(webspaceStateText, /webspace-secret-should-not-leak/);
  assert.equal(JSON.parse(webspaceStateText)["node-demo-media"].quotaBytes, 8192);

  const databasesHtml = await getText(`${baseUrl}/?section=databases&project=node-demo`);
  assert.match(databasesHtml, /Database per applicazione/);
  assert.match(databasesHtml, /Aggiungi metadata database/);
  assert.match(databasesHtml, /node_demo_external/);
  assert.match(databasesHtml, /phpmyadmin-login/);
  assert.match(databasesHtml, /OPEN-PHPMYADMIN%3Alegacy-mariadb-node-demo-external/);
  assert.match(databasesHtml, /\/actions\/phppgadmin-login/);
  assert.match(databasesHtml, /OPEN-PHPPGADMIN%3Alegacy-postgres-node-demo-external/);
  assert.doesNotMatch(databasesHtml, /\/actions\/adminer-login/);
  assert.doesNotMatch(databasesHtml, /\/actions\/pgadmin-login/);
  assert.match(databasesHtml, /Storage/);
  assert.match(databasesHtml, /Node Demo Local/);
  assert.doesNotMatch(databasesHtml, /id="app-client-portal"/);
  assert.doesNotMatch(databasesHtml, /Nessun database collegato/);
  assert.doesNotMatch(databasesHtml, /db-password-should-not-leak/);
  assert.doesNotMatch(databasesHtml, /name="ownerRole"/);

  const invalidDatabase = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "bad-name",
  });
  assert.equal(invalidDatabase.status, 422);
  assert.match(invalidDatabase.body.message, /Invalid database identifier/);

  const protectedDatabase = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "mysql",
  });
  assert.equal(protectedDatabase.status, 422);
  assert.match(protectedDatabase.body.message, /Protected system database/);

  const customPrincipalDatabase = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "node_demo_app",
    ownerRole: "node_demo_user",
  });
  assert.equal(customPrincipalDatabase.status, 422);
  assert.match(customPrincipalDatabase.body.message, /generated server-side/);

  const managedMariaPrincipal = generatedDatabasePrincipal({
    projectId: "node-demo",
    engine: "mariadb",
    databaseName: "node_demo_app",
  });

  const databasePlan = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "node_demo_app",
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databasePlan.status, 202);
  assert.equal(databasePlan.body.type, "database.create");
  assert.equal(databasePlan.body.dryRun, true);
  assert.equal(databasePlan.body.details.confirmationRequired, "CREATE-DATABASE");
  assert.equal(databasePlan.body.details.databaseTouched, false);
  assert.equal(databasePlan.body.details.credentialsExposed, false);
  assert.equal(databasePlan.body.details.ownerRole, managedMariaPrincipal);
  assert.equal(databasePlan.body.details.principalManaged, true);
  assert.equal(databasePlan.body.details.principalBindingStatus, "reserved");
  assert.doesNotMatch(JSON.stringify(databasePlan.body), /database-secret-should-not-leak/);

  const databaseApply = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "node_demo_app",
    password: fixtureCredential("created", "db", "password", "should", "not", "leak"),
    confirm: "CREATE-DATABASE",
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databaseApply.status, 202);
  assert.equal(databaseApply.body.type, "database.create.local");
  assert.equal(databaseApply.body.dryRun, false);
  assert.equal(databaseApply.body.database.id, "node-demo-mariadb-node-demo-app");
  assert.equal(databaseApply.body.database.ownerRole, managedMariaPrincipal);
  assert.equal(databaseApply.body.database.principalBindingStatus, "reserved");
  assert.equal(databaseApply.body.details.databaseTouched, false);
  assert.equal(databaseApply.body.details.credentialsExposed, false);
  assert.equal(databaseApply.body.details.credentialValueStored, true);

  const databasesAfterApply = await getJson(`${baseUrl}/control/databases`);
  assert.equal(databasesAfterApply.engines.some((engine) => engine.id === "mariadb"), true);
  assert.equal(databasesAfterApply.databases.some((database) => database.id === "node-demo-mariadb-node-demo-app"), true);
  assert.equal(existsSync(databasesFile), true);
  const databaseStateText = readFileSync(databasesFile, "utf8");
  assert.doesNotMatch(databaseStateText, /database-secret-should-not-leak/);
  assert.doesNotMatch(databaseStateText, /created-db-password-should-not-leak/);
  assert.equal(JSON.parse(databaseStateText)["node-demo-mariadb-node-demo-app"].credentialsExposed, false);
  assert.equal(JSON.parse(databaseStateText)["node-demo-mariadb-node-demo-app"].credentialRef, "secret/db/node-demo-mariadb-node-demo-app");
  assert.equal(JSON.parse(databaseStateText)["node-demo-mariadb-node-demo-app"].credentialStatus, "secret-file-set");
  assert.equal(JSON.parse(databaseStateText)["node-demo-mariadb-node-demo-app"].ownerRole, managedMariaPrincipal);
  assert.equal(JSON.parse(databaseStateText)["node-demo-mariadb-node-demo-app"].principalManaged, true);
  const principalRegistry = JSON.parse(readFileSync(databasePrincipalsFile, "utf8"));
  assert.equal(principalRegistry.bindings["node-demo-mariadb-node-demo-app"].principalName, managedMariaPrincipal);
  assert.equal(principalRegistry.bindings["node-demo-mariadb-node-demo-app"].status, "reserved");
  const createdDatabaseCredentialFile = JSON.parse(databaseStateText)["node-demo-mariadb-node-demo-app"].credentialFile;
  assert.equal(existsSync(createdDatabaseCredentialFile), true);
  assert.equal(
    createHash("sha256").update(readFileSync(createdDatabaseCredentialFile, "utf8").trim()).digest("hex"),
    createHash("sha256").update("created-db-password-should-not-leak").digest("hex"),
  );

  const databaseCreateRedirect = await fetch(`${baseUrl}/actions/database-command`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      action: "create",
      projectId: "node-demo",
      engine: "mariadb",
      name: "node_demo_redirect",
      password: fixtureCredential("redirect", "db", "password", "should", "not", "leak"),
      returnTo: "project-detail",
      openAfterCreate: "admin",
      confirm: "CREATE-DATABASE",
    }),
    redirect: "manual",
  });
  assert.equal(databaseCreateRedirect.status, 303);
  assert.equal(databaseCreateRedirect.headers.get("location"), "/?section=projects&project=node-demo#project-databases");
  assert.doesNotMatch(databaseCreateRedirect.headers.get("location") || "", /redirect-db-password-should-not-leak/);
  assert.doesNotMatch(readFileSync(databasesFile, "utf8"), /redirect-db-password-should-not-leak/);

  const databaseCreateWithoutCredential = await fetch(`${baseUrl}/actions/database-command`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      action: "create",
      projectId: "node-demo",
      engine: "mariadb",
      name: "node_demo_without_credential",
      returnTo: "project-detail",
      openAfterCreate: "admin",
      confirm: "CREATE-DATABASE",
    }),
    redirect: "manual",
  });
  assert.equal(databaseCreateWithoutCredential.status, 422);

  const stateWithManualDatabase = JSON.parse(readFileSync(databasesFile, "utf8"));
  stateWithManualDatabase["node-demo-mariadb-node-demo-without-credential"] = {
    id: "node-demo-mariadb-node-demo-without-credential",
    projectId: "node-demo",
    engine: "mariadb",
    name: "node_demo_without_credential",
    ownerRole: "node_demo_without_credential_user",
    status: "declared",
    credentialStatus: "protected",
  };
  writeFileSync(databasesFile, `${JSON.stringify(stateWithManualDatabase, null, 2)}\n`);
  const manualDatabaseAdminLocation = "/actions/phpmyadmin-login?databaseId=node-demo-mariadb-node-demo-without-credential&confirm=OPEN-PHPMYADMIN%3Anode-demo-mariadb-node-demo-without-credential";
  const manualDatabaseAdmin = await fetch(`${baseUrl}${manualDatabaseAdminLocation}`);
  assert.equal(manualDatabaseAdmin.status, 409);
  assert.match(await manualDatabaseAdmin.text(), /Salva una password per questo database/);

  const databasesHtmlAfterApply = await getText(`${baseUrl}/?section=databases&project=node-demo`);
  assert.match(databasesHtmlAfterApply, /node_demo_app/);
  assert.match(databasesHtmlAfterApply, /Plan backup/);
  assert.match(databasesHtmlAfterApply, /Plan restore drill/);

  const databaseOwnerUpdateDenied = await postJson(`${baseUrl}/actions/database-command`, {
    action: "update",
    id: "node-demo-mariadb-node-demo-app",
    projectId: "node-demo",
    displayName: "Node Demo App DB",
    ownerRole: "node_demo_runtime",
    status: "active",
    confirm: "UPDATE-DATABASE:node-demo-mariadb-node-demo-app",
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databaseOwnerUpdateDenied.status, 422);
  assert.match(databaseOwnerUpdateDenied.body.message, /ownership is immutable/);

  const databaseUpdate = await postJson(`${baseUrl}/actions/database-command`, {
    action: "update",
    id: "node-demo-mariadb-node-demo-app",
    projectId: "node-demo",
    displayName: "Node Demo App DB",
    status: "active",
    confirm: "UPDATE-DATABASE:node-demo-mariadb-node-demo-app",
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databaseUpdate.status, 202);
  assert.equal(databaseUpdate.body.type, "database.update.local");
  assert.equal(databaseUpdate.body.database.displayName, "Node Demo App DB");
  assert.equal(databaseUpdate.body.database.ownerRole, managedMariaPrincipal);
  assert.equal(databaseUpdate.body.database.status, "active");
  assert.equal(databaseUpdate.body.details.databaseTouched, false);
  assert.equal(databaseUpdate.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(databaseUpdate.body), /database-secret-should-not-leak/);

  const credentialUpdate = await postJson(`${baseUrl}/actions/database-command`, {
    action: "credential",
    id: "node-demo-mariadb-node-demo-app",
    projectId: "node-demo",
    credentialRef: "secret/db/manual-name-should-not-win",
    confirm: "ROTATE-DATABASE-CREDENTIAL:node-demo-mariadb-node-demo-app",
    password: fixtureCredential("new", "db", "password", "should", "not", "leak"),
  });
  assert.equal(credentialUpdate.status, 202);
  assert.equal(credentialUpdate.body.type, "database.credential.local");
  assert.equal(credentialUpdate.body.database.credentialRef, "secret/db/node-demo-mariadb-node-demo-app");
  assert.equal(credentialUpdate.body.database.credentialStatus, "secret-file-set");
  assert.equal(credentialUpdate.body.details.credentialValueStored, true);
  assert.equal(credentialUpdate.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(credentialUpdate.body), /new-db-password-should-not-leak/);
  assert.doesNotMatch(JSON.stringify(credentialUpdate.body), /manual-name-should-not-win/);
  const credentialStateText = readFileSync(databasesFile, "utf8");
  assert.doesNotMatch(credentialStateText, /new-db-password-should-not-leak/);
  const rotatedCredentialFile = JSON.parse(credentialStateText)["node-demo-mariadb-node-demo-app"].credentialFile;
  assert.equal(existsSync(rotatedCredentialFile), true);
  assert.equal(
    createHash("sha256").update(readFileSync(rotatedCredentialFile, "utf8").trim()).digest("hex"),
    createHash("sha256").update("new-db-password-should-not-leak").digest("hex"),
  );

  const databaseDeletePlan = await postJson(`${baseUrl}/actions/database-command`, {
    action: "delete",
    id: "node-demo-mariadb-node-demo-app",
    projectId: "node-demo",
  });
  assert.equal(databaseDeletePlan.status, 202);
  assert.equal(databaseDeletePlan.body.type, "database.delete");
  assert.equal(databaseDeletePlan.body.dryRun, true);
  assert.equal(databaseDeletePlan.body.details.backupRequiredBeforeLiveDelete, true);
  assert.equal(databaseDeletePlan.body.details.restorePointReady, true);
  assert.deepEqual(databaseDeletePlan.body.details.evidenceBlockers, []);
  assert.equal(databaseDeletePlan.body.details.databaseTouched, false);

  const legacyDeleteApply = await postJson(`${baseUrl}/actions/database-command`, {
    action: "delete",
    id: "node-demo-mariadb-node-demo-app",
    projectId: "node-demo",
    confirm: "DELETE-DATABASE:node-demo-mariadb-node-demo-app",
  });
  assert.equal(legacyDeleteApply.status, 202);
  assert.equal(legacyDeleteApply.body.type, "database.delete");
  assert.equal(legacyDeleteApply.body.dryRun, true);
  assert.equal(legacyDeleteApply.body.details.databaseTouched, false);

  const databaseBackup = await postJson(`${baseUrl}/control/databases/node-demo-mariadb-node-demo-app/backup`, {
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databaseBackup.status, 202);
  assert.equal(databaseBackup.body.type, "database.backup");
  assert.equal(databaseBackup.body.dryRun, false);
  assert.equal(databaseBackup.body.backup.status, "queued");
  assert.equal(databaseBackup.body.job.schema, "platform.backup-job/v1");
  assert.equal(databaseBackup.body.job.resources.length, 1);
  assert.equal(databaseBackup.body.job.resources[0].id, "database:node-demo-mariadb-node-demo-app");
  assert.equal("commands" in databaseBackup.body.job, false);
  assert.equal(databaseBackup.body.details.databaseTouched, false);
  assert.equal(databaseBackup.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(databaseBackup.body), /database-secret-should-not-leak/);

  const databaseRestore = await postJson(`${baseUrl}/control/databases/node-demo-mariadb-node-demo-app/restore/plan`, {
    backupRef: "latest",
  });
  assert.equal(databaseRestore.status, 202);
  assert.equal(databaseRestore.body.type, "database.restore.plan");
  assert.equal(databaseRestore.body.details.dataChanged, false);
  assert.equal(databaseRestore.body.details.databaseTouched, false);

  const databaseDeleteRequest = await postJson(`${baseUrl}/actions/database-command`, {
    action: "delete",
    id: "node-demo-mariadb-node-demo-app",
    projectId: "node-demo",
    typedName: "node_demo_app",
    idempotencyKey: "delete-node-demo-mariadb-1",
    confirm: "REQUEST-DATABASE-DELETE:node-demo-mariadb-node-demo-app",
  });
  assert.equal(databaseDeleteRequest.status, 202);
  assert.equal(databaseDeleteRequest.body.type, "database.delete.requested");
  assert.equal(databaseDeleteRequest.body.deleteOperation.status, "evidence-verified");
  assert.equal(databaseDeleteRequest.body.details.restorePointReady, true);
  assert.equal(databaseDeleteRequest.body.details.databaseTouched, false);
  assert.equal(databaseDeleteRequest.body.deleteOperation.database.credentialFile, "");
  const deleteOperationId = databaseDeleteRequest.body.deleteOperation.id;

  const duplicateDeleteRequest = await postJson(`${baseUrl}/actions/database-command`, {
    action: "delete",
    id: "node-demo-mariadb-node-demo-app",
    projectId: "node-demo",
    typedName: "node_demo_app",
    idempotencyKey: "delete-node-demo-mariadb-1",
    confirm: "REQUEST-DATABASE-DELETE:node-demo-mariadb-node-demo-app",
  });
  assert.equal(duplicateDeleteRequest.status, 202);
  assert.equal(duplicateDeleteRequest.body.deleteOperation.id, deleteOperationId);
  assert.equal(duplicateDeleteRequest.body.details.idempotent, true);

  const databaseDeleteApprove = await postJson(`${baseUrl}/actions/database-command`, {
    action: "delete-approve",
    operationId: deleteOperationId,
    typedName: "node_demo_app",
    confirm: `APPROVE-DATABASE-DELETE:${deleteOperationId}`,
  });
  assert.equal(databaseDeleteApprove.status, 202);
  assert.equal(databaseDeleteApprove.body.deleteOperation.status, "approved");
  assert.equal(databaseDeleteApprove.body.details.databaseTouched, false);

  const databaseDeleteExecute = await postJson(`${baseUrl}/actions/database-command`, {
    action: "delete-execute",
    operationId: deleteOperationId,
    typedName: "node_demo_app",
    confirm: `EXECUTE-DATABASE-DELETE:${deleteOperationId}`,
  });
  assert.equal(databaseDeleteExecute.status, 409);
  assert.match(databaseDeleteExecute.body.message, /executor is disabled/);
  assert.equal(existsSync(rotatedCredentialFile), true);
  assert.notEqual(JSON.parse(readFileSync(databasesFile, "utf8"))["node-demo-mariadb-node-demo-app"], undefined);
  assert.notEqual(JSON.parse(readFileSync(databasePrincipalsFile, "utf8")).bindings["node-demo-mariadb-node-demo-app"], undefined);
  assert.equal(JSON.parse(readFileSync(databaseDeleteOperationsFile, "utf8")).operations[deleteOperationId].status, "approved");
  assert.equal(readdirSync(path.dirname(databasesFile)).some((name) => name.startsWith(`${path.basename(databasesFile)}.tmp-`)), false);
  assert.equal(readdirSync(path.dirname(databasePrincipalsFile)).some((name) => name.startsWith(`${path.basename(databasePrincipalsFile)}.tmp-`)), false);

  const storageHtml = await getText(`${baseUrl}/?mode=advanced&section=storage`);
  assert.match(storageHtml, /ops-shell/);
  assert.doesNotMatch(storageHtml, /Declare bucket/);

  const invalidBucket = await postJson(`${baseUrl}/control/storage/buckets`, {
    projectId: "node-demo",
    name: "Bad_Bucket",
  });
  assert.equal(invalidBucket.status, 422);
  assert.match(invalidBucket.body.message, /Invalid bucket name/);

  const bucketPlan = await postJson(`${baseUrl}/control/storage/buckets`, {
    projectId: "node-demo",
    name: "node-demo-assets",
    quotaBytes: 1048576,
    accessPolicy: "private",
    accessKeyStatus: "requires-secret-file",
    secret: "storage-secret-should-not-leak",
  });
  assert.equal(bucketPlan.status, 202);
  assert.equal(bucketPlan.body.type, "storage.bucket.create");
  assert.equal(bucketPlan.body.dryRun, true);
  assert.equal(bucketPlan.body.details.confirmationRequired, "CREATE-BUCKET");
  assert.equal(bucketPlan.body.details.minioTouched, false);
  assert.equal(bucketPlan.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(bucketPlan.body), /storage-secret-should-not-leak/);

  const bucketApply = await postJson(`${baseUrl}/control/storage/buckets`, {
    projectId: "node-demo",
    name: "node-demo-assets",
    quotaBytes: 1048576,
    accessPolicy: "private",
    accessKeyStatus: "requires-secret-file",
    confirm: "CREATE-BUCKET",
    secret: "storage-secret-should-not-leak",
  });
  assert.equal(bucketApply.status, 202);
  assert.equal(bucketApply.body.type, "storage.bucket.create.local");
  assert.equal(bucketApply.body.bucket.id, "node-demo-node-demo-assets");
  assert.equal(bucketApply.body.details.minioTouched, false);
  assert.equal(bucketApply.body.details.credentialsExposed, false);

  const storageAfterApply = await getJson(`${baseUrl}/control/storage`);
  assert.equal(storageAfterApply.provider.id, "minio");
  assert.equal(storageAfterApply.buckets.some((bucket) => bucket.id === "node-demo-node-demo-assets"), true);
  assert.equal(existsSync(storageBucketsFile), true);
  const storageStateText = readFileSync(storageBucketsFile, "utf8");
  assert.doesNotMatch(storageStateText, /storage-secret-should-not-leak/);
  assert.equal(JSON.parse(storageStateText)["node-demo-node-demo-assets"].credentialsExposed, false);

  const storageHtmlAfterApply = await getText(`${baseUrl}/?mode=advanced&section=storage`);
  assert.match(storageHtmlAfterApply, /ops-shell/);
  assert.doesNotMatch(storageHtmlAfterApply, /Update access key/);
  assert.doesNotMatch(storageHtmlAfterApply, /storage-secret-should-not-leak/);

  const bucketPolicy = await postJson(`${baseUrl}/control/storage/buckets/node-demo-node-demo-assets/policy`, {
    accessPolicy: "project-private",
    confirm: "UPDATE-BUCKET-POLICY",
    secret: "storage-secret-should-not-leak",
  });
  assert.equal(bucketPolicy.status, 202);
  assert.equal(bucketPolicy.body.type, "storage.bucket.policy.local");
  assert.equal(bucketPolicy.body.bucket.accessPolicy, "project-private");
  assert.equal(bucketPolicy.body.details.minioTouched, false);
  assert.doesNotMatch(JSON.stringify(bucketPolicy.body), /storage-secret-should-not-leak/);

  const bucketLifecycle = await postJson(`${baseUrl}/control/storage/buckets/node-demo-node-demo-assets/lifecycle`, {
    retentionDays: 45,
    confirm: "UPDATE-BUCKET-LIFECYCLE",
  });
  assert.equal(bucketLifecycle.status, 202);
  assert.equal(bucketLifecycle.body.type, "storage.bucket.lifecycle.local");
  assert.equal(bucketLifecycle.body.bucket.retentionDays, 45);
  assert.equal(bucketLifecycle.body.details.minioTouched, false);

  const bucketAccessKey = await postJson(`${baseUrl}/control/storage/buckets/node-demo-node-demo-assets/access-key`, {
    accessKeyStatus: "configured",
    confirm: "UPDATE-BUCKET-ACCESS-KEY",
    secret: "storage-secret-should-not-leak",
  });
  assert.equal(bucketAccessKey.status, 202);
  assert.equal(bucketAccessKey.body.type, "storage.bucket.access_key.local");
  assert.equal(bucketAccessKey.body.bucket.accessKeyStatus, "configured");
  assert.equal(bucketAccessKey.body.details.secretMaterialChanged, "[redacted]");
  assert.equal(bucketAccessKey.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(bucketAccessKey.body), /storage-secret-should-not-leak/);

  const bucketBackup = await postJson(`${baseUrl}/control/storage/buckets/node-demo-node-demo-assets/backup`, {
    secret: "storage-secret-should-not-leak",
  });
  assert.equal(bucketBackup.status, 202);
  assert.equal(bucketBackup.body.type, "storage.bucket.backup");
  assert.equal(bucketBackup.body.dryRun, true);
  assert.equal(bucketBackup.body.details.minioTouched, false);
  assert.equal(bucketBackup.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(bucketBackup.body), /storage-secret-should-not-leak/);

  const bucketRestore = await postJson(`${baseUrl}/control/storage/buckets/node-demo-node-demo-assets/restore/plan`, {
    backupRef: "latest",
  });
  assert.equal(bucketRestore.status, 202);
  assert.equal(bucketRestore.body.type, "storage.bucket.restore.plan");
  assert.equal(bucketRestore.body.details.dataChanged, false);
  assert.equal(bucketRestore.body.details.minioTouched, false);

  const secretsHtml = await getText(`${baseUrl}/?mode=advanced&section=secrets`);
  assert.match(secretsHtml, /ops-shell/);
  assert.doesNotMatch(secretsHtml, /Declare material/);
  assert.doesNotMatch(secretsHtml, /Docker secrets/);

  const invalidMaterial = await postJson(`${baseUrl}/control/secrets/materials`, {
    projectId: "node-demo",
    targetEnv: "staging",
    materialName: "bad-name",
  });
  assert.equal(invalidMaterial.status, 422);
  assert.match(invalidMaterial.body.message, /Invalid material name/);

  const materialPlan = await postJson(`${baseUrl}/control/secrets/materials`, {
    projectId: "node-demo",
    targetEnv: "staging",
    materialName: "APP_CONFIG",
    materialKind: "application",
    materialConfigured: "true",
    rotationDays: 90,
    usageTarget: "web",
    plainValue: "material-plain-value-should-not-leak",
  });
  assert.equal(materialPlan.status, 202);
  assert.equal(materialPlan.body.type, "material.declare");
  assert.equal(materialPlan.body.dryRun, true);
  assert.equal(materialPlan.body.details.confirmationRequired, "DECLARE-MATERIAL");
  assert.equal(materialPlan.body.details.valueExposed, false);
  assert.equal(materialPlan.body.details.materialValueChanged, false);
  assert.doesNotMatch(JSON.stringify(materialPlan.body), /material-plain-value-should-not-leak/);

  const materialApply = await postJson(`${baseUrl}/control/secrets/materials`, {
    projectId: "node-demo",
    targetEnv: "staging",
    materialName: "APP_CONFIG",
    materialKind: "application",
    materialConfigured: "true",
    rotationDays: 90,
    usageTarget: "web",
    confirm: "DECLARE-MATERIAL",
    plainValue: "material-plain-value-should-not-leak",
  });
  assert.equal(materialApply.status, 202);
  assert.equal(materialApply.body.type, "material.declare.local");
  assert.equal(materialApply.body.material.id, "node-demo-staging-app-config");
  assert.equal(materialApply.body.material.valueExposed, false);
  assert.equal(materialApply.body.material.materialValueChanged, false);
  assert.doesNotMatch(JSON.stringify(materialApply.body), /material-plain-value-should-not-leak/);

  const materialInventory = await getJson(`${baseUrl}/control/secrets`);
  assert.equal(materialInventory.stores.some((store) => store.id === "docker-compose-files" && store.valueExposed === false), true);
  assert.equal(materialInventory.inventory.some((item) => item.id === "node-demo-staging-app-config"), true);
  assert.equal(existsSync(sensitiveMaterialsFile), true);
  const materialStateText = readFileSync(sensitiveMaterialsFile, "utf8");
  assert.doesNotMatch(materialStateText, /material-plain-value-should-not-leak/);
  assert.equal(JSON.parse(materialStateText)["node-demo-staging-app-config"].valueExposed, false);

  const secretsHtmlAfterApply = await getText(`${baseUrl}/?mode=advanced&section=secrets`);
  assert.match(secretsHtmlAfterApply, /ops-shell/);
  assert.doesNotMatch(secretsHtmlAfterApply, /material-plain-value-should-not-leak/);

  const vaultHtml = await getText(`${baseUrl}/?section=vault`);
  assert.match(vaultHtml, /Aggiungi secret/);
  assert.match(vaultHtml, /Secret salvati/);
  assert.doesNotMatch(vaultHtml, /vault-plain-value-should-not-leak/);
  assert.doesNotMatch(vaultHtml, /existing-github-token-should-reveal-only/);

  const vaultImportPlan = await postJson(`${baseUrl}/control/vault/import-existing`, {});
  assert.equal(vaultImportPlan.status, 202);
  assert.equal(vaultImportPlan.body.type, "vault.import-existing");
  assert.equal(vaultImportPlan.body.details.importableCount >= 3, true);
  assert.equal(vaultImportPlan.body.details.valueRead, false);
  assert.doesNotMatch(JSON.stringify(vaultImportPlan.body), /existing-github-token-should-reveal-only/);

  const vaultImportApply = await postJson(`${baseUrl}/control/vault/import-existing`, {
    confirm: "IMPORT-EXISTING-SECRETS",
  });
  assert.equal(vaultImportApply.status, 202);
  assert.equal(vaultImportApply.body.type, "vault.import-existing.local");
  assert.equal(vaultImportApply.body.items.length >= 3, true, JSON.stringify(vaultImportApply.body.items.map((item) => item.id)));
  assert.equal(vaultImportApply.body.items.some((item) => item.id === "platform-local-github-token"), true);
  assert.equal(vaultImportApply.body.items.some((item) => item.id === "platform-local-long-provider-secret"), true);
  assert.equal(vaultImportApply.body.items.some((item) => item.id === "platform-local-rclone-rclone-conf"), true);
  assert.doesNotMatch(JSON.stringify(vaultImportApply.body), /existing-github-token-should-reveal-only/);
  assert.doesNotMatch(JSON.stringify(vaultImportApply.body), new RegExp(longExistingVaultValue));
  assert.doesNotMatch(JSON.stringify(vaultImportApply.body), /existing-rclone-token-should-reveal-only/);
  assert.doesNotMatch(JSON.stringify(vaultImportApply.body), /sealedValue/);

  const importedVaultInventory = await getJson(`${baseUrl}/control/vault`);
  assert.equal(importedVaultInventory.items.some((item) => item.id === "platform-local-github-token"), true);
  assert.doesNotMatch(JSON.stringify(importedVaultInventory), /existing-github-token-should-reveal-only/);
  assert.doesNotMatch(JSON.stringify(importedVaultInventory), /sealedValue/);

  const importedVaultHtml = await getText(`${baseUrl}/?section=vault`);
  assert.match(importedVaultHtml, /Github Token/);
  assert.match(importedVaultHtml, /Mostra/);
  assert.doesNotMatch(importedVaultHtml, /existing-github-token-should-reveal-only/);

  const importedReveal = await postJson(`${baseUrl}/control/vault/secrets/platform-local-github-token/reveal`, {
    confirm: "REVEAL-VAULT-SECRET:platform-local-github-token",
  });
  assert.equal(importedReveal.status, 202);
  assert.equal(importedReveal.body.type, "vault.item.reveal.local");
  assert.equal(importedReveal.body.value, "existing-github-token-should-reveal-only");
  assert.equal(importedReveal.body.details.valueExposed, true);

  const importedLongReveal = await postJson(`${baseUrl}/control/vault/secrets/platform-local-long-provider-secret/reveal`, {
    confirm: "REVEAL-VAULT-SECRET:platform-local-long-provider-secret",
  });
  assert.equal(importedLongReveal.status, 202);
  assert.equal(importedLongReveal.body.value, longExistingVaultValue);

  const invalidVault = await postJson(`${baseUrl}/control/vault/secrets`, {
    projectId: "node-demo",
    targetEnv: "local",
    itemKey: "bad name!",
    value: "vault-plain-value-should-not-leak",
  });
  assert.equal(invalidVault.status, 422);

  const vaultPlan = await postJson(`${baseUrl}/control/vault/secrets`, {
    projectId: "node-demo",
    targetEnv: "local",
    itemKey: "app_password",
    label: "Node demo app password",
    kind: "application",
    username: "node-demo-user",
    url: "node-demo.localhost.com",
    rotationDays: 45,
    value: "vault-plain-value-should-not-leak",
  });
  assert.equal(vaultPlan.status, 202);
  assert.equal(vaultPlan.body.type, "vault.item.create");
  assert.equal(vaultPlan.body.dryRun, true);
  assert.equal(vaultPlan.body.details.valueStored, false);
  assert.equal(vaultPlan.body.details.valueExposed, false);
  assert.doesNotMatch(JSON.stringify(vaultPlan.body), /vault-plain-value-should-not-leak/);

  const vaultApply = await postJson(`${baseUrl}/control/vault/secrets`, {
    projectId: "node-demo",
    targetEnv: "local",
    itemKey: "app_password",
    label: "Node demo app password",
    kind: "application",
    username: "node-demo-user",
    url: "node-demo.localhost.com",
    rotationDays: 45,
    value: "vault-plain-value-should-not-leak",
    confirm: "STORE-VAULT-SECRET",
  });
  assert.equal(vaultApply.status, 202);
  assert.equal(vaultApply.body.type, "vault.item.create.local");
  assert.equal(vaultApply.body.item.id, "node-demo-local-app-password");
  assert.equal(vaultApply.body.item.valueStored, true);
  assert.equal(vaultApply.body.item.valueExposed, false);
  assert.doesNotMatch(JSON.stringify(vaultApply.body), /vault-plain-value-should-not-leak/);
  assert.doesNotMatch(JSON.stringify(vaultApply.body), /sealedValue/);

  const vaultRevealPlan = await postJson(`${baseUrl}/control/vault/secrets/node-demo-local-app-password/reveal`, {});
  assert.equal(vaultRevealPlan.status, 202);
  assert.equal(vaultRevealPlan.body.type, "vault.item.reveal");
  assert.equal(vaultRevealPlan.body.details.valueRead, false);
  assert.doesNotMatch(JSON.stringify(vaultRevealPlan.body), /vault-plain-value-should-not-leak/);

  const vaultRevealApply = await postJson(`${baseUrl}/control/vault/secrets/node-demo-local-app-password/reveal`, {
    confirm: "REVEAL-VAULT-SECRET:node-demo-local-app-password",
  });
  assert.equal(vaultRevealApply.status, 202);
  assert.equal(vaultRevealApply.body.type, "vault.item.reveal.local");
  assert.equal(vaultRevealApply.body.value, "vault-plain-value-should-not-leak");
  assert.equal(vaultRevealApply.body.details.valueRead, true);
  assert.equal(vaultRevealApply.body.details.valueExposed, true);

  const vaultStateText = readFileSync(vaultFile, "utf8");
  assert.doesNotMatch(vaultStateText, /vault-plain-value-should-not-leak/);
  const vaultState = JSON.parse(vaultStateText);
  assert.equal(vaultState.items["node-demo-local-app-password"].valueStored, true);
  assert.equal(vaultState.items["node-demo-local-app-password"].sealedValue.alg, "aes-256-gcm");
  assert.ok(vaultState.items["node-demo-local-app-password"].sealedValue.data.length > 8);

  const vaultInventory = await getJson(`${baseUrl}/control/vault`);
  assert.equal(vaultInventory.items.some((item) => item.id === "node-demo-local-app-password"), true);
  assert.doesNotMatch(JSON.stringify(vaultInventory), /vault-plain-value-should-not-leak/);
  assert.doesNotMatch(JSON.stringify(vaultInventory), /sealedValue/);

  const vaultHtmlAfterApply = await getText(`${baseUrl}/?section=vault`);
  assert.match(vaultHtmlAfterApply, /Node demo app password/);
  assert.doesNotMatch(vaultHtmlAfterApply, /vault-plain-value-should-not-leak/);
  assert.doesNotMatch(vaultHtmlAfterApply, /sealedValue/);

  const vaultDelete = await postJson(`${baseUrl}/control/vault/secrets/node-demo-local-app-password/delete`, {
    confirm: "DELETE-VAULT-SECRET:node-demo-local-app-password",
  });
  assert.equal(vaultDelete.status, 202);
  assert.equal(vaultDelete.body.type, "vault.item.delete.local");
  assert.equal(vaultDelete.body.details.valueRead, false);
  assert.equal(vaultDelete.body.details.valueExposed, false);
  assert.doesNotMatch(JSON.stringify(vaultDelete.body), /vault-plain-value-should-not-leak/);
  const vaultStateAfterDelete = JSON.parse(readFileSync(vaultFile, "utf8"));
  assert.equal(Boolean(vaultStateAfterDelete.items["node-demo-local-app-password"]), false);
  assert.equal(readdirSync(path.dirname(vaultFile)).some((name) => name.startsWith(`${path.basename(vaultFile)}.tmp-`)), false);

  const materialRotation = await postJson(`${baseUrl}/control/secrets/materials/node-demo-staging-app-config/rotation`, {
    rotationDays: 30,
    confirm: "UPDATE-MATERIAL-ROTATION",
    plainValue: "material-plain-value-should-not-leak",
  });
  assert.equal(materialRotation.status, 202);
  assert.equal(materialRotation.body.type, "material.rotation.local");
  assert.equal(materialRotation.body.material.rotationDays, 30);
  assert.equal(materialRotation.body.details.valueExposed, false);
  assert.doesNotMatch(JSON.stringify(materialRotation.body), /material-plain-value-should-not-leak/);

  const materialUsage = await postJson(`${baseUrl}/control/secrets/materials/node-demo-staging-app-config/usage`, {
    usageTarget: "backup-scheduler",
    confirm: "UPDATE-MATERIAL-USAGE",
  });
  assert.equal(materialUsage.status, 202);
  assert.equal(materialUsage.body.type, "material.usage.local");
  assert.deepEqual(materialUsage.body.material.usageTargets, ["backup-scheduler"]);

  const materialAccess = await postJson(`${baseUrl}/control/secrets/materials/node-demo-staging-app-config/access`, {
    purpose: "incident-review",
    confirm: "RECORD-MATERIAL-ACCESS",
    plainValue: "material-plain-value-should-not-leak",
  });
  assert.equal(materialAccess.status, 202);
  assert.equal(materialAccess.body.type, "material.access.local");
  assert.equal(materialAccess.body.details.valueRead, false);
  assert.equal(materialAccess.body.details.valueExposed, false);
  assert.doesNotMatch(JSON.stringify(materialAccess.body), /material-plain-value-should-not-leak/);

  const resourcesSummaryBeforeLimits = await getJson(`${baseUrl}/control/resources/summary`);
  assert.equal(resourcesSummaryBeforeLimits.rows.some((row) => row.applicationId === "node-demo" && row.cpu.includes("3.500%")), true);
  assert.equal(resourcesSummaryBeforeLimits.rows.some((row) => row.cpu.includes("7.000%")), false);
  assert.equal(JSON.stringify(resourcesSummaryBeforeLimits).includes("0 core"), false);

  const invalidResourceLimit = await postJson(`${baseUrl}/control/resources/limits`, {
    projectId: "node-demo",
    memoryMb: -1,
  });
  assert.equal(invalidResourceLimit.status, 422);
  assert.match(invalidResourceLimit.body.message, /Memory MB/);

  const resourceLimitPlan = await postJson(`${baseUrl}/control/resources/limits`, {
    projectId: "node-demo",
    cpuMillicores: 500,
    memoryMb: 256,
    diskMb: 1024,
    secret: "resource-limit-secret-should-not-leak",
  });
  assert.equal(resourceLimitPlan.status, 202);
  assert.equal(resourceLimitPlan.body.type, "resources.limits");
  assert.equal(resourceLimitPlan.body.dryRun, true);
  assert.equal(resourceLimitPlan.body.details.confirmationRequired, "UPDATE-RESOURCE-LIMITS");
  assert.equal(resourceLimitPlan.body.details.dockerTouched, false);
  assert.doesNotMatch(JSON.stringify(resourceLimitPlan.body), /resource-limit-secret-should-not-leak/);

  const resourceLimitApply = await postJson(`${baseUrl}/control/resources/limits`, {
    projectId: "node-demo",
    cpuMillicores: 750,
    memoryMb: 512,
    diskMb: 2048,
    confirm: "UPDATE-RESOURCE-LIMITS",
    secret: "resource-limit-secret-should-not-leak",
  });
  assert.equal(resourceLimitApply.status, 202);
  assert.equal(resourceLimitApply.body.type, "resources.limits.local");
  assert.equal(resourceLimitApply.body.dryRun, false);
  assert.equal(resourceLimitApply.body.resourceLimit.projectId, "node-demo");
  assert.equal(resourceLimitApply.body.resourceLimit.cpuMillicores, 750);
  assert.equal(resourceLimitApply.body.resourceLimit.memoryMb, 512);
  assert.equal(resourceLimitApply.body.resourceLimit.diskMb, 2048);
  assert.equal(resourceLimitApply.body.resourceLimit.dockerTouched, false);
  assert.doesNotMatch(JSON.stringify(resourceLimitApply.body), /resource-limit-secret-should-not-leak/);

  const resourceSummary = await getJson(`${baseUrl}/control/resources/summary`);
  const nodeDemoLimit = resourceSummary.projectLimits.find((limit) => limit.projectId === "node-demo");
  assert.equal(nodeDemoLimit.cpuMillicores, 750);
  assert.equal(nodeDemoLimit.memoryMb, 512);
  assert.equal(nodeDemoLimit.diskMb, 2048);
  assert.equal(existsSync(resourceLimitsFile), true);
  const resourceLimitText = readFileSync(resourceLimitsFile, "utf8");
  assert.doesNotMatch(resourceLimitText, /resource-limit-secret-should-not-leak/);
  assert.equal(JSON.parse(resourceLimitText)["node-demo"].diskMb, 2048);

  const securityHtml = await getText(`${baseUrl}/?section=security`);
  assert.match(securityHtml, /ops-shell/);
  assert.doesNotMatch(securityHtml, /Update policy/);
  assert.doesNotMatch(securityHtml, /security-secret-should-not-leak/);

  const invalidSecurityPolicy = await postJson(`${baseUrl}/control/security/policy`, {
    scope: "global",
    wafMode: "evil",
  });
  assert.equal(invalidSecurityPolicy.status, 422);
  assert.match(invalidSecurityPolicy.body.message, /WAF mode/);

  const securityPolicyPlan = await postJson(`${baseUrl}/control/security/policy`, {
    scope: "global",
    wafMode: "monitor",
    rateLimitTier: "standard",
    adminProtection: "local-only",
    securityHeaders: "report-only",
    cloudflareAccess: "plan-only-local",
    passkeyAdminAuth: "external-idp-or-passkey-app",
    secret: "security-secret-should-not-leak",
  });
  assert.equal(securityPolicyPlan.status, 202);
  assert.equal(securityPolicyPlan.body.type, "security.policy");
  assert.equal(securityPolicyPlan.body.dryRun, true);
  assert.equal(securityPolicyPlan.body.details.confirmationRequired, "UPDATE-SECURITY-POLICY");
  assert.equal(securityPolicyPlan.body.details.providerTouched, false);
  assert.equal(securityPolicyPlan.body.details.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(securityPolicyPlan.body), /security-secret-should-not-leak/);

  const securityPolicyApply = await postJson(`${baseUrl}/actions/security-command`, {
    action: "policy",
    scope: "global",
    wafMode: "blocking",
    rateLimitTier: "strict",
    adminProtection: "required",
    securityHeaders: "strict",
    cloudflareAccess: "plan-only-local",
    passkeyAdminAuth: "required",
    confirm: "UPDATE-SECURITY-POLICY",
    secret: "security-secret-should-not-leak",
  });
  assert.equal(securityPolicyApply.status, 202);
  assert.equal(securityPolicyApply.body.type, "security.policy.local");
  assert.equal(securityPolicyApply.body.dryRun, false);
  assert.equal(securityPolicyApply.body.securityPolicy.scope, "global");
  assert.equal(securityPolicyApply.body.securityPolicy.wafMode, "blocking");
  assert.equal(securityPolicyApply.body.securityPolicy.rateLimitTier, "strict");
  assert.equal(securityPolicyApply.body.securityPolicy.adminProtection, "required");
  assert.equal(securityPolicyApply.body.securityPolicy.securityHeaders, "strict");
  assert.equal(securityPolicyApply.body.securityPolicy.providerTouched, false);
  assert.equal(securityPolicyApply.body.securityPolicy.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(securityPolicyApply.body), /security-secret-should-not-leak/);

  const securitySummary = await getJson(`${baseUrl}/control/security/summary`);
  assert.equal(securitySummary.waf, "blocking");
  assert.equal(securitySummary.rateLimit, "strict");
  assert.equal(securitySummary.adminProtection, "required");
  assert.equal(securitySummary.securityHeaders, "strict");
  assert.equal(securitySummary.policies.some((policy) => policy.scope === "global" && policy.providerTouched === false && policy.productionEvidence === false), true);
  assert.equal(existsSync(securityPoliciesFile), true);
  const securityPoliciesText = readFileSync(securityPoliciesFile, "utf8");
  assert.doesNotMatch(securityPoliciesText, /security-secret-should-not-leak/);
  assert.equal(JSON.parse(securityPoliciesText).global.wafMode, "blocking");

  const identityInitial = await getJson(`${baseUrl}/control/identity`);
  assert.equal(identityInitial.adminUsers.some((user) => user.id === "local-admin" && user.credentialsExposed === false), true);
  assert.equal(identityInitial.roles.some((role) => role.permissions.includes("control:*")), true);
  assert.equal(identityInitial.guardrails.liveIdentityProviderTouched, false);

  const invalidIdentityUser = await postJson(`${baseUrl}/control/identity/admin-users`, {
    email: "not-an-email",
  });
  assert.equal(invalidIdentityUser.status, 422);
  assert.match(invalidIdentityUser.body.message, /Invalid admin email/);

  const roleApply = await postJson(`${baseUrl}/control/identity/roles`, {
    id: "platform-operator",
    name: "Platform Operator",
    permissions: "control:read,projects:write,audit:read",
    confirm: "DECLARE-IDENTITY-ROLE",
    secret: "identity-secret-should-not-leak",
  });
  assert.equal(roleApply.status, 202);
  assert.equal(roleApply.body.type, "identity.role.local");
  assert.equal(roleApply.body.role.id, "platform-operator");
  assert.equal(roleApply.body.role.permissions.includes("projects:write"), true);
  assert.equal(roleApply.body.role.providerTouched, false);
  assert.doesNotMatch(JSON.stringify(roleApply.body), /identity-secret-should-not-leak/);

  const teamApply = await postJson(`${baseUrl}/actions/identity-command`, {
    action: "team",
    id: "platform-ops",
    name: "Platform Ops",
    roleIds: "platform-operator",
    members: "local-admin",
    confirm: "DECLARE-IDENTITY-TEAM",
    secret: "identity-secret-should-not-leak",
  });
  assert.equal(teamApply.status, 202);
  assert.equal(teamApply.body.type, "identity.team.local");
  assert.equal(teamApply.body.team.roleIds.includes("platform-operator"), true);
  assert.equal(teamApply.body.team.providerTouched, false);

  const adminUserPlan = await postJson(`${baseUrl}/control/identity/admin-users`, {
    email: "ops-admin@example.com",
    displayName: "Ops Admin",
    roleIds: "platform-operator",
    teamIds: "platform-ops",
    mfaRequired: true,
    passkeyRequired: true,
    secret: "identity-secret-should-not-leak",
  });
  assert.equal(adminUserPlan.status, 202);
  assert.equal(adminUserPlan.body.type, "identity.admin-user");
  assert.equal(adminUserPlan.body.dryRun, true);
  assert.equal(adminUserPlan.body.details.confirmationRequired, "DECLARE-ADMIN-USER");
  assert.equal(adminUserPlan.body.details.credentialsStored, false);
  assert.equal(adminUserPlan.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(adminUserPlan.body), /identity-secret-should-not-leak/);

  const adminUserApply = await postJson(`${baseUrl}/control/identity/admin-users`, {
    email: "ops-admin@example.com",
    displayName: "Ops Admin",
    roleIds: "platform-operator",
    teamIds: "platform-ops",
    mfaRequired: true,
    passkeyRequired: true,
    confirm: "DECLARE-ADMIN-USER",
    secret: "identity-secret-should-not-leak",
  });
  assert.equal(adminUserApply.status, 202);
  assert.equal(adminUserApply.body.type, "identity.admin-user.local");
  assert.equal(adminUserApply.body.adminUser.email, "ops-admin@example.com");
  assert.equal(adminUserApply.body.adminUser.mfaStatus, "required");
  assert.equal(adminUserApply.body.adminUser.passkeyStatus, "required");
  assert.equal(adminUserApply.body.adminUser.credentialsExposed, false);

  const sessionApply = await postJson(`${baseUrl}/control/identity/sessions`, {
    id: "control-center-session",
    maxAgeMinutes: 240,
    cookieFlags: "HttpOnly,Secure,SameSite=Lax",
    confirm: "UPDATE-SESSION-POLICY",
    token: "identity-secret-should-not-leak",
  });
  assert.equal(sessionApply.status, 202);
  assert.equal(sessionApply.body.type, "identity.session.local");
  assert.equal(sessionApply.body.sessionPolicy.maxAgeMinutes, 240);
  assert.equal(sessionApply.body.sessionPolicy.cookieFlags.includes("SameSite=Lax"), true);
  assert.equal(sessionApply.body.sessionPolicy.valueExposed, false);

  const reviewApply = await postJson(`${baseUrl}/control/identity/access-reviews`, {
    scope: "admin-users",
    reviewer: "local-admin",
    status: "passed",
    notes: "quarterly review token=identity-secret-should-not-leak",
    confirm: "RECORD-ACCESS-REVIEW",
  });
  assert.equal(reviewApply.status, 202);
  assert.equal(reviewApply.body.type, "identity.access-review.local");
  assert.equal(reviewApply.body.accessReview.status, "passed");
  assert.equal(reviewApply.body.accessReview.providerTouched, false);
  assert.doesNotMatch(JSON.stringify(reviewApply.body), /identity-secret-should-not-leak/);

  const identityAfterApply = await getJson(`${baseUrl}/control/identity`);
  assert.equal(identityAfterApply.adminUsers.some((user) => user.email === "ops-admin@example.com" && user.credentialsExposed === false), true);
  assert.equal(identityAfterApply.teams.some((team) => team.id === "platform-ops"), true);
  assert.equal(identityAfterApply.sessionPolicies.some((policy) => policy.id === "control-center-session" && policy.maxAgeMinutes === 240), true);
  assert.equal(identityAfterApply.accessReviews.some((review) => review.scope === "admin-users" && review.status === "passed"), true);
  assert.equal(existsSync(identityAccessFile), true);
  const identityAccessText = readFileSync(identityAccessFile, "utf8");
  assert.doesNotMatch(identityAccessText, /identity-secret-should-not-leak/);
  assert.equal(JSON.parse(identityAccessText).users["ops-admin"].email, "ops-admin@example.com");

  const identityHtml = await getText(`${baseUrl}/?mode=advanced&section=identity`);
  assert.match(identityHtml, /ops-shell/);
  assert.doesNotMatch(identityHtml, /Declare admin user/);
  assert.doesNotMatch(identityHtml, /identity-secret-should-not-leak/);

  const logsHtml = await getText(`${baseUrl}/?section=activity`);
  assert.match(logsHtml, /Stato/);
  assert.doesNotMatch(logsHtml, /Errori, avvisi e problemi/);
  assert.doesNotMatch(logsHtml, /Alert aperti/);

  const invalidAlert = await postJson(`${baseUrl}/control/alerts/record`, {
    service: "waf",
    severity: "panic",
  });
  assert.equal(invalidAlert.status, 422);
  assert.match(invalidAlert.body.message, /alert severity/);

  const alertPlan = await postJson(`${baseUrl}/control/alerts/record`, {
    service: "waf",
    severity: "critical",
    summary: "WAF block spike",
    secret: "alert-secret-should-not-leak",
  });
  assert.equal(alertPlan.status, 202);
  assert.equal(alertPlan.body.type, "alert.record");
  assert.equal(alertPlan.body.dryRun, true);
  assert.equal(alertPlan.body.details.deliveryAttempted, false);
  assert.equal(alertPlan.body.details.productionEvidence, false);
  assert.equal(alertPlan.body.details.confirmationRequired, "RECORD-ALERT");
  assert.doesNotMatch(JSON.stringify(alertPlan.body), /alert-secret-should-not-leak/);

  const alertApply = await postJson(`${baseUrl}/actions/alert-command`, {
    action: "record",
    service: "waf",
    severity: "critical",
    summary: "WAF block spike",
    confirm: "RECORD-ALERT",
    secret: "alert-secret-should-not-leak",
  });
  assert.equal(alertApply.status, 202);
  assert.equal(alertApply.body.type, "alert.record.local");
  assert.equal(alertApply.body.dryRun, false);
  assert.equal(alertApply.body.alert.service, "waf");
  assert.equal(alertApply.body.alert.status, "open");
  assert.equal(alertApply.body.alert.deliveryAttempted, false);
  assert.equal(alertApply.body.alert.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(alertApply.body), /alert-secret-should-not-leak/);

  const channelApply = await postJson(`${baseUrl}/actions/alert-command`, {
    action: "channel",
    channel: "email",
    status: "configured",
    deliveryMode: "secret-file",
    confirm: "UPDATE-NOTIFICATION-CHANNEL",
    secret: "alert-secret-should-not-leak",
  });
  assert.equal(channelApply.status, 202);
  assert.equal(channelApply.body.type, "alerts.channel.local");
  assert.equal(channelApply.body.notificationChannel.channel, "email");
  assert.equal(channelApply.body.notificationChannel.status, "configured");
  assert.equal(channelApply.body.notificationChannel.plainValueExposed, false);
  assert.equal(channelApply.body.notificationChannel.deliveryAttempted, false);

  const logsSummary = await getJson(`${baseUrl}/control/logs/summary`);
  assert.equal(logsSummary.openAlerts.some((alert) => alert.id === alertApply.body.alert.id), true);
  assert.equal(logsSummary.notificationChannels.some((channel) => channel.channel === "email" && channel.status === "configured"), true);
  assert.doesNotMatch(JSON.stringify(logsSummary), /alert-secret-should-not-leak/);

  const alerts = await getJson(`${baseUrl}/control/alerts`);
  assert.equal(alerts.alerts.some((alert) => alert.id === alertApply.body.alert.id), true);
  assert.equal(alerts.notificationChannels.some((channel) => channel.channel === "email"), true);

  const resolveAlert = await postJson(`${baseUrl}/control/alerts/${alertApply.body.alert.id}/resolve`, {
    confirm: "RESOLVE-ALERT",
    secret: "alert-secret-should-not-leak",
  });
  assert.equal(resolveAlert.status, 202);
  assert.equal(resolveAlert.body.type, "alert.resolve.local");
  assert.equal(resolveAlert.body.alert.status, "resolved");
  assert.equal(existsSync(alertsFile), true);
  assert.equal(existsSync(notificationChannelsFile), true);
  const alertsText = readFileSync(alertsFile, "utf8");
  const notificationChannelsText = readFileSync(notificationChannelsFile, "utf8");
  assert.doesNotMatch(alertsText, /alert-secret-should-not-leak/);
  assert.doesNotMatch(notificationChannelsText, /alert-secret-should-not-leak/);
  assert.equal(JSON.parse(alertsText)[alertApply.body.alert.id].status, "resolved");
  assert.equal(JSON.parse(notificationChannelsText).email.status, "configured");

  const settingsHtml = await getText(`${baseUrl}/?section=settings`);
  assert.match(settingsHtml, /ops-shell/);
  assert.doesNotMatch(settingsHtml, /Settings/);
  assert.doesNotMatch(settingsHtml, /Provider Connections/);
  assert.doesNotMatch(settingsHtml, /AppShell/);
  assert.equal(settingsHtml.includes(["file", "vendor"].join(":")), false);

  const providerConnections = await getJson(`${baseUrl}/control/provider-connections`);
  assert.equal(providerConnections.providerConnections.some((connection) => connection.id === "cloudflare"), true);
  assert.equal(providerConnections.providerConnections.some((connection) => connection.id === "github"), true);
  assert.equal(providerConnections.providerConnections.every((connection) => connection.credentialValueExposed === false && connection.liveProviderTouched === false), true);

  const providerPlan = await postJson(`${baseUrl}/control/provider-connections/cloudflare`, {
    status: "requires-verify-remote",
    accountLabel: "node-demo-zone",
    scope: "localhost.com",
    cloudflareToken: "provider-secret-should-not-leak",
  });
  assert.equal(providerPlan.status, 202);
  assert.equal(providerPlan.body.type, "provider.connection");
  assert.equal(providerPlan.body.dryRun, true);
  assert.equal(providerPlan.body.details.confirmationRequired, "UPDATE-PROVIDER-CONNECTION");
  assert.equal(providerPlan.body.details.privateMaterialConfigured, true);
  assert.equal(providerPlan.body.details.providerTouched, false);
  assert.equal(providerPlan.body.details.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(providerPlan.body), /provider-secret-should-not-leak/);

  const providerApply = await postJson(`${baseUrl}/actions/settings-command`, {
    action: "provider-connection",
    id: "cloudflare",
    status: "requires-verify-remote",
    accountLabel: "node-demo-zone",
    scope: "localhost.com",
    confirm: "UPDATE-PROVIDER-CONNECTION",
    cloudflareToken: "provider-secret-should-not-leak",
  });
  assert.equal(providerApply.status, 202);
  assert.equal(providerApply.body.type, "provider.connection.local");
  assert.equal(providerApply.body.dryRun, false);
  assert.equal(providerApply.body.providerConnection.id, "cloudflare");
  assert.equal(providerApply.body.providerConnection.status, "requires-verify-remote");
  assert.equal(providerApply.body.providerConnection.credentialValueExposed, false);
  assert.equal(providerApply.body.providerConnection.productionEvidence, false);
  assert.equal(existsSync(providerConnectionsFile), true);
  const providerConnectionsText = readFileSync(providerConnectionsFile, "utf8");
  assert.doesNotMatch(providerConnectionsText, /provider-secret-should-not-leak/);
  assert.equal(JSON.parse(providerConnectionsText).cloudflare.status, "requires-verify-remote");

  const invalidSettings = await postJson(`${baseUrl}/control/settings/local`, {
    preferredMode: "simple",
    environmentMode: "local",
    baseDomain: "../secret",
  });
  assert.equal(invalidSettings.status, 422);
  assert.match(invalidSettings.body.message, /base domain/);

  const settingsPlan = await postJson(`${baseUrl}/control/settings/local`, {
    preferredMode: "advanced",
    environmentMode: "staging",
    baseDomain: "localhost.com",
    cloudflareConnectionStatus: "requires-verify-remote",
    githubConnectionStatus: "dry-run",
    smtpAlertStatus: "requires-secret-file",
    secret: "settings-secret-should-not-leak",
  });
  assert.equal(settingsPlan.status, 202);
  assert.equal(settingsPlan.body.type, "settings.update");
  assert.equal(settingsPlan.body.dryRun, true);
  assert.equal(settingsPlan.body.details.confirmationRequired, "UPDATE-SETTINGS");
  assert.equal(settingsPlan.body.details.runtimeEnvironmentChanged, false);
  assert.equal(settingsPlan.body.details.providerTouched, false);
  assert.equal(settingsPlan.body.details.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(settingsPlan.body), /settings-secret-should-not-leak/);

  const settingsApply = await postJson(`${baseUrl}/actions/settings-command`, {
    action: "update",
    preferredMode: "advanced",
    environmentMode: "staging",
    baseDomain: "localhost.com",
    cloudflareConnectionStatus: "requires-verify-remote",
    githubConnectionStatus: "dry-run",
    smtpAlertStatus: "requires-secret-file",
    confirm: "UPDATE-SETTINGS",
    secret: "settings-secret-should-not-leak",
  });
  assert.equal(settingsApply.status, 202);
  assert.equal(settingsApply.body.type, "settings.update.local");
  assert.equal(settingsApply.body.dryRun, false);
  assert.equal(settingsApply.body.settings.preferredMode, "advanced");
  assert.equal(settingsApply.body.settings.environmentMode, "staging");
  assert.equal(settingsApply.body.settings.baseDomain, "localhost.com");
  assert.equal(settingsApply.body.settings.runtimeEnvironmentChanged, false);
  assert.equal(settingsApply.body.settings.providerTouched, false);
  assert.equal(settingsApply.body.settings.productionEvidence, false);

  const settingsSummary = await getJson(`${baseUrl}/control/settings`);
  assert.equal(settingsSummary.preferredMode, "advanced");
  assert.equal(settingsSummary.environmentMode, "staging");
  assert.equal(settingsSummary.baseDomain, "localhost.com");
  assert.equal(settingsSummary.providerTouched, false);
  assert.equal(existsSync(settingsFile), true);
  const settingsText = readFileSync(settingsFile, "utf8");
  assert.doesNotMatch(settingsText, /settings-secret-should-not-leak/);
  assert.equal(JSON.parse(settingsText).preferredMode, "advanced");

  const deployPlan = await postJson(`${baseUrl}/control/applications/node-demo/deploy`, {
    branch: "main",
    commit: "abc1234",
    cloudflareToken: "super-secret-token-should-not-leak",
  });
  assert.equal(deployPlan.status, 202);
  assert.equal(deployPlan.body.type, "application.deploy");
  assert.equal(deployPlan.body.dryRun, true);
  assert.equal(deployPlan.body.projectId, "node-demo");
  assert.equal(deployPlan.body.deployment.action, "deploy");
  assert.equal(deployPlan.body.deployment.status, "planned");
  assert.equal(deployPlan.body.deployment.releaseEvidence, "local-plan-only");
  assert.equal(deployPlan.body.deployment.productionApproval, "required-for-production");
  assert.doesNotMatch(JSON.stringify(deployPlan.body), /super-secret-token-should-not-leak/);
  assert.doesNotMatch(JSON.stringify(deployPlan.body), /cloudflareToken/);

  const rollbackPlan = await postJson(`${baseUrl}/control/applications/node-demo/rollback`, {
    rollbackTarget: "previous-release",
  });
  assert.equal(rollbackPlan.status, 202);
  assert.equal(rollbackPlan.body.type, "application.rollback");
  assert.equal(rollbackPlan.body.deployment.action, "rollback");

  const deployments = await getJson(`${baseUrl}/control/deployments`);
  assert.equal(deployments.deployments.some((deployment) => deployment.id === deployPlan.body.deployment.id), true);
  assert.equal(deployments.deployments.some((deployment) => deployment.id === rollbackPlan.body.deployment.id), true);
  assert.equal(existsSync(deploymentsFile), true);
  const deploymentText = readFileSync(deploymentsFile, "utf8");
  assert.doesNotMatch(deploymentText, /super-secret-token-should-not-leak/);
  assert.doesNotMatch(deploymentText, /cloudflareToken/);
  assert.equal(deploymentText.trim().split(/\r?\n/).length >= 2, true);

  const deploymentHtml = await getText(`${baseUrl}/?mode=advanced&section=deployments`);
  assert.match(deploymentHtml, /ops-shell/);
  assert.doesNotMatch(deploymentHtml, /Deployment History/);

  const legacyBackupsHtml = await getText(`${baseUrl}/?section=backups`);
  assert.match(legacyBackupsHtml, /ops-shell/);
  assert.match(legacyBackupsHtml, /data-ops-nav-group="status" data-ops-nav-expanded="true"/);
  assert.doesNotMatch(legacyBackupsHtml, /data-ops-nav-group="backups"|ops-nav-panel-backups|Backup applicazioni|File manager backup|backupProject=/);

  const backupFiles = await getJson(`${baseUrl}/control/backups/files`);
  assert.equal(backupFiles.available, true);
  assert.equal(backupFiles.entries.some((entry) => entry.name === "postgres" && entry.type === "directory"), true);

  const postgresBackupFiles = await getJson(`${baseUrl}/control/backups/files?path=postgres`);
  assert.equal(postgresBackupFiles.entries.some((entry) => entry.name === "node-demo-20260629.dump" && entry.removable === true), true);
  assert.equal(postgresBackupFiles.entries.some((entry) => entry.name === "preview.txt"), true);

  const applicationBackupFiles = await getJson(`${baseUrl}/control/backups/files?path=applications/node-demo`);
  assert.equal(applicationBackupFiles.available, true);
  assert.equal(applicationBackupFiles.entries.some((entry) => entry.name === "node-demo-source-20260629.tar.gz"), true);

  const backupPreview = await getJson(`${baseUrl}/control/backups/preview?path=postgres/preview.txt`);
  assert.equal(backupPreview.mode, "safe-redacted-preview");
  assert.match(backupPreview.content, /token=\[redacted\]/);
  assert.match(backupPreview.content, /healthy=true/);
  assert.doesNotMatch(JSON.stringify(backupPreview), /backup-secret-should-not-leak/);

  const dumpPreview = await getJson(`${baseUrl}/control/backups/preview?path=postgres/node-demo-20260629.dump`);
  assert.equal(dumpPreview.type, "postgres-custom-dump");
  assert.match(dumpPreview.message, /restore drill/);
  assert.equal(dumpPreview.mode, "metadata-only");
  assert.equal(dumpPreview.content, "");

  const sqlGzipPreview = await getJson(`${baseUrl}/control/backups/preview?path=postgres/node-demo-20260629.sql.gz`);
  assert.equal(sqlGzipPreview.type, "sql-gzip");
  assert.equal(sqlGzipPreview.mode, "metadata-only");
  assert.equal(sqlGzipPreview.content, "");
  assert.doesNotMatch(JSON.stringify(sqlGzipPreview), /copy-row-secret-should-not-leak/);

  const blockedBackupDelete = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "delete-file",
    path: "postgres/node-demo-20260629.dump.sha256",
    confirm: "wrong",
  });
  assert.equal(blockedBackupDelete.status, 409);
  assert.equal(existsSync(path.join(backupsRoot, "postgres", "node-demo-20260629.dump.sha256")), true);

  const backupDelete = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "delete-file",
    path: "postgres/node-demo-20260629.dump.sha256",
    confirm: "ELIMINA-BACKUP-FILE",
  });
  assert.equal(backupDelete.status, 202);
  assert.equal(backupDelete.body.type, "backup.file.delete");
  assert.equal(backupDelete.body.dryRun, false);
  assert.equal(backupDelete.body.details.fileDeleted, true);
  assert.equal(existsSync(path.join(backupsRoot, "postgres", "node-demo-20260629.dump.sha256")), false);

  const backupPlan = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "backup",
    scope: "all",
    secret: "backup-secret-should-not-leak",
  });
  assert.equal(backupPlan.status, 202);
  assert.equal(backupPlan.body.type, "backup.run");
  assert.equal(backupPlan.body.dryRun, false);
  assert.equal(backupPlan.body.backup.action, "backup");
  assert.equal(backupPlan.body.backup.status, "queued");
  assert.equal(backupPlan.body.backup.productionEvidence, false);
  assert.equal(backupPlan.body.job.status, "queued");
  assert.equal(existsSync(path.join(backupJobsDir, "queued", `${backupPlan.body.job.id}.json`)), true);
  assert.doesNotMatch(JSON.stringify(backupPlan.body), /backup-secret-should-not-leak/);

  const appBackupPlan = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "backup",
    scope: "application",
    projectId: "node-demo",
    secret: "backup-secret-should-not-leak",
  });
  assert.equal(appBackupPlan.status, 202);
  assert.equal(appBackupPlan.body.type, "backup.run");
  assert.equal(appBackupPlan.body.backup.scope, "app-node-demo");
  assert.equal(appBackupPlan.body.job.schema, "platform.backup-job/v1");
  assert.equal(appBackupPlan.body.job.scope.kind, "application");
  assert.equal(appBackupPlan.body.job.scope.id, "node-demo");
  assert.equal("commands" in appBackupPlan.body.job, false);
  assert.deepEqual(new Set(appBackupPlan.body.job.resources.map((item) => item.kind)), new Set(["source", "database"]));
  const appBackupDatabaseResources = appBackupPlan.body.job.resources.filter((item) => item.kind === "database");
  assert.equal(appBackupDatabaseResources.length >= 2, true);
  assert.equal(new Set(appBackupDatabaseResources.map((item) => item.id)).size, appBackupDatabaseResources.length);
  assert.equal(appBackupPlan.body.details.backupMode, "all");
  assert.equal(existsSync(path.join(backupJobsDir, "queued", `${appBackupPlan.body.job.id}.json`)), true);
  assert.doesNotMatch(JSON.stringify(appBackupPlan.body), /backup-secret-should-not-leak/);

  const appSourceOnlyBackup = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "backup",
    scope: "application",
    projectId: "node-demo",
    backupMode: "source",
  });
  assert.equal(appSourceOnlyBackup.status, 202);
  assert.equal(appSourceOnlyBackup.body.job.resources.length, 1);
  assert.equal(appSourceOnlyBackup.body.job.resources[0].kind, "source");
  assert.equal("commands" in appSourceOnlyBackup.body.job, false);
  assert.equal(appSourceOnlyBackup.body.details.backupMode, "source");

  const appDatabaseOnlyBackup = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "backup",
    scope: "application",
    projectId: "node-demo",
    backupMode: "database",
  });
  assert.equal(appDatabaseOnlyBackup.status, 202);
  assert.equal(appDatabaseOnlyBackup.body.job.resources.length >= 2, true);
  assert.equal(appDatabaseOnlyBackup.body.job.resources.every((item) => item.kind === "database"), true);
  assert.deepEqual(new Set(appDatabaseOnlyBackup.body.job.resources.map((item) => item.engine)), new Set(["postgres", "mariadb"]));
  assert.equal(appDatabaseOnlyBackup.body.details.backupMode, "database");

  const appRestorePlan = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "restore",
    scope: "application",
    projectId: "node-demo",
    backupRef: "manifests/manifest-node-demo.json",
    restoreMode: "source",
    secret: "backup-secret-should-not-leak",
  });
  assert.equal(appRestorePlan.status, 202);
  assert.equal(appRestorePlan.body.type, "restore.queue");
  assert.equal(appRestorePlan.body.dryRun, false);
  assert.equal(appRestorePlan.body.details.scope, "app-node-demo");
  assert.equal(appRestorePlan.body.details.projectId, "node-demo");
  assert.equal(appRestorePlan.body.details.backupRef, "manifests/manifest-node-demo.json");
  assert.equal(appRestorePlan.body.details.restoreMode, "source");
  assert.equal(appRestorePlan.body.details.dataChanged, false);
  assert.equal(appRestorePlan.body.backup.action, "restore-drill");
  assert.equal(appRestorePlan.body.backup.status, "queued");
  assert.equal(appRestorePlan.body.backup.scope, "app-node-demo");
  assert.equal(appRestorePlan.body.backup.backupRef, "manifests/manifest-node-demo.json");
  assert.equal(appRestorePlan.body.job.resources.length, 1);
  assert.equal(appRestorePlan.body.job.resources[0].kind, "source");
  assert.equal(appRestorePlan.body.job.sourceManifestPath, "manifests/manifest-node-demo.json");
  assert.doesNotMatch(JSON.stringify(appRestorePlan.body), /backup-secret-should-not-leak/);

  const appDatabaseRestorePlan = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "restore",
    scope: "application",
    projectId: "node-demo",
    backupRef: "manifests/manifest-node-demo.json",
    restoreMode: "database",
  });
  assert.equal(appDatabaseRestorePlan.status, 202);
  assert.equal(appDatabaseRestorePlan.body.type, "restore.queue");
  assert.equal(appDatabaseRestorePlan.body.details.restoreMode, "database");
  assert.equal(appDatabaseRestorePlan.body.job.resources.length, 3);
  assert.equal(appDatabaseRestorePlan.body.job.resources.every((item) => item.kind === "database"), true);
  assert.equal("commands" in appDatabaseRestorePlan.body.job, false);

  const restorePlan = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "restore",
    scope: "all",
    backupRef: "latest",
  });
  assert.equal(restorePlan.status, 202);
  assert.equal(restorePlan.body.type, "restore.queue");
  assert.equal(restorePlan.body.dryRun, false);
  assert.equal(restorePlan.body.details.dataChanged, false);
  assert.equal(restorePlan.body.backup.action, "restore-drill");
  assert.equal(restorePlan.body.backup.status, "queued");
  assert.equal(restorePlan.body.backup.backupRef, "manifests/manifest-platform.json");
  assert.equal(existsSync(path.join(backupJobsDir, "queued", `${restorePlan.body.job.id}.json`)), true);

  const backupJobs = await getJson(`${baseUrl}/control/backups/jobs`);
  assert.equal(backupJobs.jobs.some((job) => job.id === backupPlan.body.job.id && job.queueStatus === "queued"), true);
  assert.equal(backupJobs.jobs.some((job) => job.id === appBackupPlan.body.job.id && job.scope?.kind === "application" && job.scope?.id === "node-demo" && job.queueStatus === "queued"), true);
  assert.equal(backupJobs.jobs.some((job) => job.id === restorePlan.body.job.id && job.queueStatus === "queued"), true);

  const backupRecords = await getJson(`${baseUrl}/control/backups/records`);
  assert.equal(backupRecords.records.some((record) => record.id === backupPlan.body.backup.id), true);
  assert.equal(backupRecords.records.some((record) => record.id === appBackupPlan.body.backup.id && record.scope === "app-node-demo"), true);
  assert.equal(backupRecords.records.some((record) => record.id === appRestorePlan.body.backup.id && record.scope === "app-node-demo"), true);
  assert.equal(backupRecords.records.some((record) => record.id === restorePlan.body.backup.id), true);
  assert.equal(existsSync(backupRecordsFile), true);
  const backupRecordsText = readFileSync(backupRecordsFile, "utf8");
  assert.equal(backupRecordsText.trim().split(/\r?\n/).length >= 2, true);
  assert.doesNotMatch(backupRecordsText, /backup-secret-should-not-leak/);
  assert.doesNotMatch(await getText(`${baseUrl}/?mode=advanced&section=backup-restore`), /Backup History/);

  const localApply = await postJson(`${baseUrl}/control/subdomains/apply`, {
    environment: "local",
    projectId: "node-demo",
    hostname: "node-demo-preview.localhost.com",
    confirm: "APPLY-LOCAL",
    cloudflareToken: "super-secret-token-should-not-leak",
  });
  assert.equal(localApply.status, 202);
  assert.equal(localApply.body.type, "subdomain.apply.local");
  assert.equal(localApply.body.id, localApply.body.operationId);
  assert.equal(localApply.body.projectId, "node-demo");
  assert.equal(localApply.body.environment, "local");
  assert.equal(localApply.body.dryRun, false);
  assert.equal(localApply.body.details.productionEvidence, false);
  assert.equal(localApply.body.steps.every((step) => step.operationId === localApply.body.id), true);
  assert.equal(localApply.body.steps.every((step) => step.output === "sanitized"), true);
  assert.doesNotMatch(JSON.stringify(localApply.body), /super-secret-token-should-not-leak/);
  assert.doesNotMatch(JSON.stringify(localApply.body), /cloudflareToken/);

  const domainsWithPreview = await getJson(`${baseUrl}/control/domains`);
  assert.equal(domainsWithPreview.subdomains.some((item) => item.hostname === "node-demo-preview.localhost.com"), true);

  const operations = await getJson(`${baseUrl}/control/operations`);
  const applyOperation = operations.operations.find((operation) => operation.id === localApply.body.id);
  assert.ok(applyOperation);
  assert.equal(applyOperation.type, "subdomain.apply.local");
  assert.equal(applyOperation.requestedBy, "test-owner");
  assert.equal(applyOperation.requestedByRole, "owner");
  assert.equal(applyOperation.reportPath, null);
  assert.equal(applyOperation.errorCode, null);
  assert.equal(applyOperation.errorMessage, null);
  assert.ok(applyOperation.startedAt);
  assert.ok(applyOperation.finishedAt);
  assert.equal(Array.isArray(applyOperation.steps), true);
  assert.equal(applyOperation.steps.every((step) => step.operationId === applyOperation.id), true);
  assert.equal(applyOperation.steps.every((step) => step.startedAt && step.finishedAt && step.output === "sanitized"), true);

  const operationById = await getJson(`${baseUrl}/control/operations/${localApply.body.id}`);
  assert.equal(operationById.id, localApply.body.id);
  assert.equal(existsSync(operationsFile), true);
  const operationText = readFileSync(operationsFile, "utf8");
  assert.doesNotMatch(operationText, /super-secret-token-should-not-leak/);
  assert.doesNotMatch(operationText, /cloudflareToken/);
  const operationLines = operationText.trim().split(/\r?\n/);
  assert.equal(operationLines.length >= 2, true);
  for (const line of operationLines) {
    const operation = JSON.parse(line);
    assert.ok(operation.id);
    assert.ok(operation.operationId);
    assert.ok(operation.type);
    assert.ok(operation.environment);
    assert.equal(Array.isArray(operation.steps), true);
  }

  const removePreview = await postJson(`${baseUrl}/control/subdomains/node-demo-preview-localhost-com/remove/apply`, {
    confirm: "REMOVE-SUBDOMAIN",
  });
  assert.equal(removePreview.status, 202);

  const domainsAfterRemove = await getJson(`${baseUrl}/control/domains`);
  assert.equal(domainsAfterRemove.subdomains.some((item) => item.hostname === "node-demo-preview.localhost.com"), false);

  const audit = await getJson(`${baseUrl}/control/audit`);
  assert.equal(audit.audit.length >= 2, true);
  const auditText = JSON.stringify(audit);
  assert.doesNotMatch(auditText, /super-secret-token-should-not-leak/);
  assert.doesNotMatch(auditText, /cloudflareToken/);
  assert.equal(existsSync(auditFile), true);
  const auditLines = readFileSync(auditFile, "utf8").trim().split(/\r?\n/);
  assert.equal(auditLines.length >= 2, true);
  for (const line of auditLines) {
    const event = JSON.parse(line);
    assert.ok(event.timestamp);
    assert.ok(event.action);
    assert.ok(event.requestId);
  }

  const validDatabaseState = readFileSync(databasesFile, "utf8");
  writeFileSync(databasesFile, "{not-valid-database-json\n", { mode: 0o600 });
  const corruptDatabaseResponse = await fetch(`${baseUrl}/control/databases`, { headers: { accept: "application/json" } });
  assert.equal(corruptDatabaseResponse.status, 500);
  assert.equal(readFileSync(databasesFile, "utf8"), "{not-valid-database-json\n");
  writeFileSync(databasesFile, validDatabaseState, { mode: 0o600 });

  const validPrincipalRegistry = readFileSync(databasePrincipalsFile, "utf8");
  writeFileSync(databasePrincipalsFile, "{not-valid-principal-json\n", { mode: 0o600 });
  const corruptPrincipalResponse = await fetch(`${baseUrl}/control/databases`, { headers: { accept: "application/json" } });
  assert.equal(corruptPrincipalResponse.status, 500);
  assert.equal(readFileSync(databasePrincipalsFile, "utf8"), "{not-valid-principal-json\n");
  writeFileSync(databasePrincipalsFile, validPrincipalRegistry, { mode: 0o600 });

  writeFileSync(vaultFile, "{not-valid-json\n", { mode: 0o600 });
  const corruptVaultResponse = await fetch(`${baseUrl}/control/vault`, { headers: { accept: "application/json" } });
  assert.equal(corruptVaultResponse.status, 500);
  assert.equal(readFileSync(vaultFile, "utf8"), "{not-valid-json\n");

  assert.equal(stderr, "");
});

test("Admin Control Center defaults to platform-only without hosted project discovery", async (t) => {
  const isolatedRoot = path.join(infraRoot, ".tmp", "control-center-tests", `platform-only-${randomUUID()}`);
  const isolatedProjectsRoot = path.join(isolatedRoot, "projects");
  const isolatedStateDir = path.join(isolatedRoot, "state");
  const isolatedProjectStateFile = path.join(isolatedStateDir, "projects.json");
  const isolatedAuditFile = path.join(isolatedStateDir, "audit.jsonl");
  const isolatedOperationsFile = path.join(isolatedStateDir, "operations.jsonl");
  const isolatedApplicationsFile = path.join(isolatedStateDir, "applications.json");
  const isolatedDomainsFile = path.join(isolatedStateDir, "domains.json");
  const isolatedDatabasesFile = path.join(isolatedStateDir, "databases.json");
  const isolatedStorageBucketsFile = path.join(isolatedStateDir, "storage-buckets.json");
  const isolatedSensitiveMaterialsFile = path.join(isolatedStateDir, "sensitive-materials.json");
  const isolatedWorkerJobsFile = path.join(isolatedStateDir, "worker-jobs.json");
  const isolatedIdentityAccessFile = path.join(isolatedStateDir, "identity-access.json");
  const isolatedDeploymentsFile = path.join(isolatedStateDir, "deployments.jsonl");
  const isolatedBackupRecordsFile = path.join(isolatedStateDir, "backups.jsonl");
  const isolatedBackupJobsDir = path.join(isolatedStateDir, "backup-jobs");
  const isolatedResourceLimitsFile = path.join(isolatedStateDir, "resource-limits.json");
  const isolatedSecurityPoliciesFile = path.join(isolatedStateDir, "security-policies.json");
  const isolatedAlertsFile = path.join(isolatedStateDir, "alerts.json");
  const isolatedNotificationChannelsFile = path.join(isolatedStateDir, "notification-channels.json");
  const isolatedProviderConnectionsFile = path.join(isolatedStateDir, "provider-connections.json");
  const isolatedSettingsFile = path.join(isolatedStateDir, "settings.json");
  const isolatedWebspacesFile = path.join(isolatedStateDir, "webspaces.json");

  rmSync(isolatedRoot, { recursive: true, force: true });
  mkdirSync(path.join(isolatedProjectsRoot, "shadow-project"), { recursive: true });
  mkdirSync(isolatedStateDir, { recursive: true });
  writeFileSync(path.join(isolatedProjectsRoot, "shadow-project", "package.json"), `${JSON.stringify({ scripts: { start: "node server.js" } }, null, 2)}\n`);

  const port = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_ENV: "local",
      CONTROL_CENTER_AUTH_MODE: "test-disabled",
      CONTROL_CENTER_DATABASE_LIVE_APPLY: "false",
      CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "false",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      PROJECTS_ROOT: isolatedProjectsRoot,
      PROJECT_STATE_FILE: isolatedProjectStateFile,
      PROJECT_AUDIT_FILE: isolatedAuditFile,
      PROJECT_OPERATIONS_FILE: isolatedOperationsFile,
      PROJECT_APPLICATIONS_FILE: isolatedApplicationsFile,
      PROJECT_DOMAINS_FILE: isolatedDomainsFile,
      PROJECT_DATABASES_FILE: isolatedDatabasesFile,
      PROJECT_STORAGE_BUCKETS_FILE: isolatedStorageBucketsFile,
      PROJECT_SENSITIVE_MATERIALS_FILE: isolatedSensitiveMaterialsFile,
      PROJECT_WORKER_JOBS_FILE: isolatedWorkerJobsFile,
      PROJECT_IDENTITY_ACCESS_FILE: isolatedIdentityAccessFile,
      PROJECT_DEPLOYMENTS_FILE: isolatedDeploymentsFile,
      PROJECT_BACKUP_RECORDS_FILE: isolatedBackupRecordsFile,
      PROJECT_BACKUP_JOBS_DIR: isolatedBackupJobsDir,
      PROJECT_RESOURCE_LIMITS_FILE: isolatedResourceLimitsFile,
      PROJECT_SECURITY_POLICIES_FILE: isolatedSecurityPoliciesFile,
      PROJECT_ALERTS_FILE: isolatedAlertsFile,
      PROJECT_NOTIFICATION_CHANNELS_FILE: isolatedNotificationChannelsFile,
      PROJECT_PROVIDER_CONNECTIONS_FILE: isolatedProviderConnectionsFile,
      PROJECT_SETTINGS_FILE: isolatedSettingsFile,
      PROJECT_WEBSPACES_FILE: isolatedWebspacesFile,
      PROJECT_DOCKER_STATS_FILE: path.join(isolatedStateDir, "docker-stats.json"),
      CONTROL_CENTER_HOST: "portal.localhost.com",
      DOCS_HOST: "docs.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  t.after(async () => {
    await stopChild(child);
    rmSync(isolatedRoot, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHealth(`${baseUrl}/__health`, child);

  const overview = await getJson(`${baseUrl}/control/overview`);
  assert.equal(overview.projects.total, 0);
  assert.equal(overview.applications.total, 0);
  assert.equal(overview.subdomains.total, 0);

  const applications = await getJson(`${baseUrl}/control/applications`);
  assert.deepEqual(applications.applications, []);

  const applicationsHtml = await getText(`${baseUrl}/?section=applications`);
  assert.match(applicationsHtml, /ops-shell/);
  assert.doesNotMatch(applicationsHtml, /Shadow Project/);

  assert.equal(stderr, "");
});

test("Admin Control Center browses project root symlinks inside projects root", async (t) => {
  const isolatedRoot = path.join(infraRoot, ".tmp", "control-center-tests", `root-symlink-${randomUUID()}`);
  const isolatedProjectsRoot = path.join(isolatedRoot, "projects");
  const isolatedStateDir = path.join(isolatedRoot, "state");
  const realProjectRoot = path.join(isolatedProjectsRoot, "fiplatform");
  const aliasProjectRoot = path.join(isolatedProjectsRoot, "fireport");
  const outsideRoot = path.join(isolatedRoot, "outside");

  rmSync(isolatedRoot, { recursive: true, force: true });
  mkdirSync(path.join(realProjectRoot, ".platform"), { recursive: true });
  mkdirSync(outsideRoot, { recursive: true });
  mkdirSync(isolatedStateDir, { recursive: true });
  writeFileSync(path.join(realProjectRoot, "package.json"), `${JSON.stringify({ scripts: { start: "node server.js" } }, null, 2)}\n`);
  writeFileSync(path.join(realProjectRoot, "server.mjs"), "console.log('ok');\n");
  writeFileSync(path.join(realProjectRoot, ".platform", "project.json"), `${JSON.stringify({ projects: [{ slug: "fiplatform", name: "fiplatform", type: "node", aliases: ["fireport"], summary: "fiplatform app with a fireport alias." }], type: "node" }, null, 2)}\n`);
  symlinkSync("fiplatform", aliasProjectRoot, "dir");
  symlinkSync(outsideRoot, path.join(realProjectRoot, "outside-link"), "dir");

  const port = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_ENV: "local",
      CONTROL_CENTER_AUTH_MODE: "test-disabled",
      CONTROL_CENTER_DATABASE_LIVE_APPLY: "false",
      CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "true",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      PROJECTS_ROOT: isolatedProjectsRoot,
      ...isolatedStateEnv(isolatedStateDir),
      PROJECT_DOCKER_STATS_FILE: path.join(isolatedStateDir, "docker-stats.json"),
      CONTROL_CENTER_HOST: "portal.localhost.com",
      DOCS_HOST: "docs.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  t.after(async () => {
    await stopChild(child);
    rmSync(isolatedRoot, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHealth(`${baseUrl}/__health`, child);

  const projects = await getJson(`${baseUrl}/control/projects`);
  const aliasProject = projects.projects.find((project) => project.slug === "fiplatform");
  assert.equal(projects.projects.some((project) => project.slug === "fireport"), false);
  assert.deepEqual(aliasProject?.aliases, ["fireport"]);
  assert.equal(aliasProject?.filesAvailable, true);
  assert.equal(aliasProject?.filesystemExists, true);

  const files = await getJson(`${baseUrl}/control/projects/fiplatform/files`);
  assert.equal(files.available, true);
  assert.equal(files.entries.some((entry) => entry.name === "package.json"), true);
  assert.equal(files.entries.some((entry) => entry.name === "outside-link" && entry.type === "symlink" && entry.browsable === false), true);

  const blocked = await fetch(`${baseUrl}/control/projects/fiplatform/files?path=outside-link`, { headers: { accept: "application/json" } });
  assert.equal(blocked.status, 422);

  assert.equal(stderr, "");
});

test("Admin Control Center OIDC passkey guard", async (t) => {
  prepareFixture();
  const issuer = "https://identity.example.test/realms/platform";
  const requiredAcr = "urn:platform:loa:passkey";
  const clientId = "platform-control-center";
  const { publicKey, privateKey } = await generateKeyPair("RS256", { extractable: true });
  const { privateKey: wrongPrivateKey } = await generateKeyPair("RS256");
  const { privateKey: disallowedAlgorithmPrivateKey } = await generateKeyPair("PS256");
  const publicJwk = { ...(await exportJWK(publicKey)), alg: "RS256", use: "sig", kid: "test-key" };
  let expectedNonce = "";
  let tokenRequests = 0;
  let redirectedTokenRequests = 0;

  const idpPort = await freePort();
  const idp = createHttpServer(async (req, res) => {
    if (req.url === "/jwks") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [publicJwk] }));
      return;
    }
    if (req.url === "/token-redirect-target") {
      redirectedTokenRequests += 1;
      res.writeHead(500).end();
      return;
    }
    if (req.url === "/token" && req.method === "POST") {
      tokenRequests += 1;
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      const code = form.get("code") || "";
      assert.equal(form.get("grant_type"), "authorization_code");
      assert.equal(form.get("client_id"), clientId);
      assert.match(form.get("code_verifier") || "", /^[A-Za-z0-9_-]{43,128}$/);
      if (code === "redirect-token") {
        res.writeHead(307, { location: `http://127.0.0.1:${idpPort}/token-redirect-target` }).end();
        return;
      }
      const role = code === "viewer" ? "viewer" : "owner";
      const acr = code === "password-auth" ? "urn:platform:loa:password" : requiredAcr;
      const authTime = Math.floor(Date.now() / 1000) - (code === "stale-owner" ? 360 : 0);
      const subject = code === "backchannel-owner"
        ? "test-backchannel-owner"
        : code === "audit-failure-owner"
          ? "test-audit-failure-owner"
          : code === "provider-audit-failure-owner"
            ? "test-provider-audit-failure-owner"
          : code.startsWith("provider-event-")
            ? "test-provider-event-owner"
            : code === "account-disabled-owner" ? "test-account-disabled-owner" : `test-${role}`;
      const sessionId = code === "backchannel-owner"
        ? "sid-backchannel-owner"
        : code === "audit-failure-owner"
          ? "sid-audit-failure-owner"
          : code.startsWith("provider-event-") || code === "account-disabled-owner" || code === "provider-audit-failure-owner"
            ? `sid-${code}`
            : `sid-test-${role}`;
      const idToken = await new SignJWT({
        nonce: expectedNonce,
        acr,
        amr: acr === requiredAcr ? ["webauthn"] : ["pwd"],
        auth_time: authTime,
        sid: sessionId,
        email: `${role}@example.test`,
        name: `Test ${role}`,
        realm_access: { roles: [role] },
      })
        .setProtectedHeader({ alg: "RS256", kid: "test-key" })
        .setIssuer(issuer)
        .setAudience(clientId)
        .setSubject(subject)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ id_token: idToken, token_type: "Bearer", expires_in: 300 }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => idp.listen(idpPort, "127.0.0.1", resolve));

  const port = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_ENV: "test",
      CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
      CONTROL_CENTER_AUTH_STORE: "memory",
      CONTROL_CENTER_OIDC_ISSUER: issuer,
      CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: `${issuer}/protocol/openid-connect/auth`,
      CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: `http://127.0.0.1:${idpPort}/token`,
      CONTROL_CENTER_OIDC_JWKS_URI: `http://127.0.0.1:${idpPort}/jwks`,
      CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
      CONTROL_CENTER_OIDC_CLIENT_ID: clientId,
      CONTROL_CENTER_OIDC_REQUIRED_ACR: requiredAcr,
      CONTROL_CENTER_OIDC_REQUIRED_AMR: "webauthn",
      CONTROL_CENTER_LOGIN_MAX_ATTEMPTS: "2",
      CONTROL_CENTER_DATABASE_LIVE_APPLY: "false",
      CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: "true",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      PROJECTS_ROOT: projectsRoot,
      ...isolatedStateEnv(stateDir),
      PROJECT_DOCKER_STATS_FILE: dockerStatsFile,
      CONTROL_CENTER_HOST: "portal.example.test",
      DOCS_HOST: "docs.example.test",
      PROJECT_HOST_SUFFIX: ".example.test",
      NODE_PROJECT_HOSTS: "node-demo=node-demo.example.test",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  t.after(async () => {
    await stopChild(child);
    await new Promise((resolve) => idp.close(resolve));
    rmSync(testRoot, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHealth(`${baseUrl}/__health`, child);

  const denied = await fetch(`${baseUrl}/control/overview`, { headers: { accept: "application/json" } });
  assert.equal(denied.status, 401);
  assert.equal((await denied.json()).error, "admin_auth_required");

  const deniedMutation = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ slug: "node-demo", enabled: "0" }),
  });
  assert.equal(deniedMutation.status, 401);

  const loginPage = await fetch(`${baseUrl}/`);
  assert.equal(loginPage.status, 401);
  const loginHtml = await loginPage.text();
  assert.match(loginHtml, /Accesso amministrativo/);
  assert.match(loginHtml, /Accedi con passkey/);
  assert.doesNotMatch(loginHtml, /type="password"|current-password/);

  const legacyPasswordLogin = await fetch(`${baseUrl}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ password: fixtureCredential("must", "never", "be", "accepted") }),
  });
  assert.equal(legacyPasswordLogin.status, 401);
  assert.equal(tokenRequests, 0);

  async function beginLogin() {
    const response = await fetch(`${baseUrl}/auth/login`, { redirect: "manual" });
    assert.equal(response.status, 303);
    const location = new URL(response.headers.get("location"));
    assert.equal(location.searchParams.get("code_challenge_method"), "S256");
    assert.equal(location.searchParams.get("acr_values"), requiredAcr);
    expectedNonce = location.searchParams.get("nonce") || "";
    return location.searchParams.get("state") || "";
  }

  const rejectedState = await beginLogin();
  const rejected = await fetch(`${baseUrl}/auth/callback?code=password-auth&state=${encodeURIComponent(rejectedState)}`, { redirect: "manual" });
  assert.equal(rejected.status, 403);
  assert.equal(rejected.headers.get("set-cookie"), null);

  const viewerState = await beginLogin();
  const viewerLogin = await fetch(`${baseUrl}/auth/callback?code=viewer&state=${encodeURIComponent(viewerState)}`, { redirect: "manual" });
  assert.equal(viewerLogin.status, 303);
  const viewerCookie = cookieHeader(responseSetCookies(viewerLogin));
  const viewerMutation = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { cookie: viewerCookie, "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ slug: "node-demo", enabled: "0" }),
  });
  assert.equal(viewerMutation.status, 403);

  const redirectState = await beginLogin();
  const redirectAttempt = await fetch(`${baseUrl}/auth/callback?code=redirect-token&state=${encodeURIComponent(redirectState)}`, { redirect: "manual" });
  assert.equal(redirectAttempt.status, 401);
  assert.equal(redirectedTokenRequests, 0);

  const ownerState = await beginLogin();
  const ownerLogin = await fetch(`${baseUrl}/auth/callback?code=owner&state=${encodeURIComponent(ownerState)}`, { redirect: "manual" });
  assert.equal(ownerLogin.status, 303);
  const ownerSetCookies = responseSetCookies(ownerLogin);
  const ownerSetCookieText = ownerSetCookies.join("\n");
  assert.match(ownerSetCookieText, /__Host-platform_cc_session=/);
  assert.match(ownerSetCookieText, /__Host-platform_cc_csrf=/);
  assert.match(ownerSetCookieText, /HttpOnly/);
  assert.match(ownerSetCookieText, /Secure/);
  assert.match(ownerSetCookieText, /SameSite=Lax/);
  const ownerCookie = cookieHeader(ownerSetCookies);
  const ownerCsrf = cookieValue(ownerSetCookies, "__Host-platform_cc_csrf");

  const replayCallback = await fetch(`${baseUrl}/auth/callback?code=owner&state=${encodeURIComponent(ownerState)}`, { redirect: "manual" });
  assert.equal(replayCallback.status, 401);
  assert.equal(replayCallback.headers.get("set-cookie"), null);

  const authedOverview = await fetch(`${baseUrl}/control/overview`, { headers: { cookie: ownerCookie, accept: "application/json" } });
  assert.equal(authedOverview.status, 200);
  assert.equal((await authedOverview.json()).title, "Admin Control Center");

  const missingOrigin = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { cookie: ownerCookie, "content-type": "application/x-www-form-urlencoded", "x-csrf-token": ownerCsrf, accept: "application/json" },
    body: new URLSearchParams({ slug: "node-demo", enabled: "0", _csrf: ownerCsrf }),
  });
  assert.equal(missingOrigin.status, 403);
  assert.equal((await missingOrigin.json()).error, "csrf_origin_rejected");

  const siblingOrigin = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { cookie: ownerCookie, origin: "https://sibling.example.test", "sec-fetch-site": "same-site", "content-type": "application/x-www-form-urlencoded", "x-csrf-token": ownerCsrf, accept: "application/json" },
    body: new URLSearchParams({ slug: "node-demo", enabled: "0", _csrf: ownerCsrf }),
  });
  assert.equal(siblingOrigin.status, 403);
  assert.equal((await siblingOrigin.json()).error, "csrf_origin_rejected");

  const validMutation = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { cookie: ownerCookie, origin: "https://portal.example.test", "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded", "x-csrf-token": ownerCsrf },
    body: new URLSearchParams({ slug: "node-demo", enabled: "0", _csrf: ownerCsrf }),
    redirect: "manual",
  });
  assert.equal(validMutation.status, 303);

  const oversized = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { cookie: ownerCookie, origin: "https://portal.example.test", "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded", "x-csrf-token": ownerCsrf, accept: "application/json" },
    body: `slug=node-demo&_csrf=${encodeURIComponent(ownerCsrf)}&padding=${"x".repeat(70 * 1024)}`,
  });
  assert.equal(oversized.status, 413);
  assert.equal((await oversized.json()).error, "payload_too_large");

  const staleState = await beginLogin();
  const staleLogin = await fetch(`${baseUrl}/auth/callback?code=stale-owner&state=${encodeURIComponent(staleState)}`, { redirect: "manual" });
  assert.equal(staleLogin.status, 303);
  const staleCookies = responseSetCookies(staleLogin);
  const staleCookie = cookieHeader(staleCookies);
  const staleCsrf = cookieValue(staleCookies, "__Host-platform_cc_csrf");
  const staleSensitive = await fetch(`${baseUrl}/actions/vault-command`, {
    method: "POST",
    headers: { cookie: staleCookie, origin: "https://portal.example.test", "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded", "x-csrf-token": staleCsrf, accept: "application/json" },
    body: new URLSearchParams({ action: "reveal", _csrf: staleCsrf }),
  });
  assert.equal(staleSensitive.status, 428);
  assert.equal((await staleSensitive.json()).error, "admin_reauthentication_required");

  const ownerAudit = await getJson(`${baseUrl}/control/audit`, { headers: { cookie: ownerCookie } });
  const loginAudit = ownerAudit.audit.find((event) => event.action === "admin.oidc.login.success" && event.target === "test-owner");
  assert.equal(loginAudit.actor, "test-owner");

  const backchannelState = await beginLogin();
  const backchannelLogin = await fetch(`${baseUrl}/auth/callback?code=backchannel-owner&state=${encodeURIComponent(backchannelState)}`, { redirect: "manual" });
  assert.equal(backchannelLogin.status, 303);
  const backchannelCookie = cookieHeader(responseSetCookies(backchannelLogin));
  const auditFailureState = await beginLogin();
  const auditFailureLogin = await fetch(`${baseUrl}/auth/callback?code=audit-failure-owner&state=${encodeURIComponent(auditFailureState)}`, { redirect: "manual" });
  assert.equal(auditFailureLogin.status, 303);
  const auditFailureCookie = cookieHeader(responseSetCookies(auditFailureLogin));
  async function createLogoutToken({
    claims = {},
    omit = [],
    signer = privateKey,
    alg = "RS256",
    kid = "test-key",
    tokenIssuer = issuer,
    tokenAudience = clientId,
    jti = `logout-${randomUUID()}`,
    issuedAt = Math.floor(Date.now() / 1000),
  } = {}) {
    const payload = {
      events: {
        "http://schemas.openid.net/event/backchannel-logout": {},
        revoke_offline_access: true,
      },
      sid: "sid-backchannel-owner",
      sub: "test-backchannel-owner",
      ...claims,
    };
    for (const claim of omit) delete payload[claim];
    let token = new SignJWT(payload)
      .setProtectedHeader({ alg, kid })
      .setIssuer(tokenIssuer)
      .setAudience(tokenAudience)
      .setIssuedAt(issuedAt)
      .setExpirationTime("5m");
    if (jti !== null) token = token.setJti(jti);
    return token.sign(signer);
  }

  async function submitBackchannelToken(token) {
    return fetch(`${baseUrl}/auth/backchannel-logout`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ logout_token: token }),
    });
  }

  async function createProviderSecurityEventToken({
    eventType = "urn:platform-infrastructure:event:authorization-changed",
    eventValue = {},
    claims = {},
    omit = [],
    signer = privateKey,
    tokenIssuer = issuer,
    tokenAudience = clientId,
    tokenType = "secevent+jwt",
    jti = `provider-event-${randomUUID()}`,
    issuedAt = Math.floor(Date.now() / 1000),
  } = {}) {
    const payload = {
      events: { [eventType]: eventValue },
      sub: "test-provider-event-owner",
      ...claims,
    };
    for (const claim of omit) delete payload[claim];
    let token = new SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", kid: "test-key", typ: tokenType })
      .setIssuer(tokenIssuer)
      .setAudience(tokenAudience)
      .setIssuedAt(issuedAt)
      .setExpirationTime("5m");
    if (jti !== null) token = token.setJti(jti);
    return token.sign(signer);
  }

  async function submitProviderSecurityEvent(token, contentType = "application/secevent+jwt") {
    return fetch(`${baseUrl}/auth/provider-security-event`, {
      method: "POST",
      headers: { "content-type": contentType, accept: "application/json" },
      body: token,
    });
  }

  const logoutToken = await createLogoutToken({ jti: "logout-backchannel-owner-1" });
  const duplicateField = await fetch(`${baseUrl}/auth/backchannel-logout`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `logout_token=${encodeURIComponent(logoutToken)}&logout_token=${encodeURIComponent(logoutToken)}`,
  });
  assert.equal(duplicateField.status, 400);

  const invalidLogoutTokens = [
    "not-a-compact-jwt",
    await createLogoutToken({ signer: wrongPrivateKey }),
    await createLogoutToken({ tokenIssuer: "https://wrong-issuer.example.test/realms/platform" }),
    await createLogoutToken({ tokenAudience: "wrong-client" }),
    await createLogoutToken({ claims: { nonce: "forbidden" } }),
    await createLogoutToken({ claims: { events: { "urn:wrong:event": {} } } }),
    await createLogoutToken({ claims: { events: { "http://schemas.openid.net/event/backchannel-logout": {}, revoke_offline_access: false } } }),
    await createLogoutToken({ claims: { events: { "http://schemas.openid.net/event/backchannel-logout": {}, revoke_offline_access: "true" } } }),
    await createLogoutToken({ claims: { events: { "http://schemas.openid.net/event/backchannel-logout": {}, revoke_offline_access: true, "urn:unexpected:event": {} } } }),
    await createLogoutToken({ omit: ["sid", "sub"] }),
    await createLogoutToken({ jti: null }),
    await createLogoutToken({ issuedAt: Math.floor(Date.now() / 1000) - 6 * 60 }),
    await createLogoutToken({ signer: disallowedAlgorithmPrivateKey, alg: "PS256", kid: "ps256-key" }),
    await createLogoutToken({ claims: { sid: { invalid: true } } }),
  ];
  for (const invalidLogoutToken of invalidLogoutTokens) {
    const invalidResponse = await submitBackchannelToken(invalidLogoutToken);
    assert.equal(invalidResponse.status, 400);
    assert.equal((await invalidResponse.json()).error, "oidc_backchannel_logout_rejected");
  }
  const beforeBackchannel = await fetch(`${baseUrl}/control/overview`, { headers: { cookie: backchannelCookie, accept: "application/json" } });
  assert.equal(beforeBackchannel.status, 200);
  const backchannel = await fetch(`${baseUrl}/auth/backchannel-logout`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8", accept: "application/json" },
    body: new URLSearchParams({ logout_token: logoutToken }),
  });
  assert.equal(backchannel.status, 200);
  assert.deepEqual(await backchannel.json(), { ok: true, replayed: false, revoked: 1 });
  const revokedByProvider = await fetch(`${baseUrl}/control/overview`, { headers: { cookie: backchannelCookie, accept: "application/json" } });
  assert.equal(revokedByProvider.status, 401);
  const unaffectedOwner = await fetch(`${baseUrl}/control/overview`, { headers: { cookie: ownerCookie, accept: "application/json" } });
  assert.equal(unaffectedOwner.status, 200);
  const replayedBackchannel = await fetch(`${baseUrl}/auth/backchannel-logout`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ logout_token: logoutToken }),
  });
  assert.equal(replayedBackchannel.status, 200);
  assert.deepEqual(await replayedBackchannel.json(), { ok: true, replayed: true, revoked: 0 });

  const providerEventCookies = [];
  for (const code of ["provider-event-a", "provider-event-b"]) {
    const state = await beginLogin();
    const login = await fetch(`${baseUrl}/auth/callback?code=${code}&state=${encodeURIComponent(state)}`, { redirect: "manual" });
    assert.equal(login.status, 303);
    providerEventCookies.push(cookieHeader(responseSetCookies(login)));
  }
  for (const cookie of providerEventCookies) {
    assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie, accept: "application/json" } })).status, 200);
  }

  const validAuthorizationEvent = await createProviderSecurityEventToken({ jti: "provider-authorization-change-1" });
  const wrongContentType = await submitProviderSecurityEvent(validAuthorizationEvent, "application/x-www-form-urlencoded");
  assert.equal(wrongContentType.status, 415);
  const invalidProviderEvents = [
    "not-a-compact-jwt",
    await createProviderSecurityEventToken({ signer: wrongPrivateKey }),
    await createProviderSecurityEventToken({ tokenIssuer: "https://wrong-issuer.example.test/realms/platform" }),
    await createProviderSecurityEventToken({ tokenAudience: "wrong-client" }),
    await createProviderSecurityEventToken({ tokenAudience: [clientId, "wrong-client"] }),
    await createProviderSecurityEventToken({ tokenType: "JWT" }),
    await createProviderSecurityEventToken({ eventType: "urn:platform-infrastructure:event:unsupported" }),
    await createProviderSecurityEventToken({ eventValue: { reason: "unexpected" } }),
    await createProviderSecurityEventToken({ claims: { events: {
      "urn:platform-infrastructure:event:authorization-changed": {},
      "urn:platform-infrastructure:event:account-disabled": {},
    } } }),
    await createProviderSecurityEventToken({ claims: { sid: "sid-must-not-narrow-account-events" } }),
    await createProviderSecurityEventToken({ claims: { nonce: "forbidden" } }),
    await createProviderSecurityEventToken({ omit: ["sub"] }),
    await createProviderSecurityEventToken({ jti: null }),
    await createProviderSecurityEventToken({ issuedAt: Math.floor(Date.now() / 1000) - 6 * 60 }),
    await createProviderSecurityEventToken({ issuedAt: Math.floor(Date.now() / 1000) + 1 }),
  ];
  for (const invalidProviderEvent of invalidProviderEvents) {
    const response = await submitProviderSecurityEvent(invalidProviderEvent);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "oidc_provider_security_event_rejected");
  }
  const authorizationEventResponse = await submitProviderSecurityEvent(validAuthorizationEvent);
  assert.equal(authorizationEventResponse.status, 200);
  assert.deepEqual(await authorizationEventResponse.json(), { ok: true, replayed: false, revoked: 2 });
  for (const cookie of providerEventCookies) {
    assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie, accept: "application/json" } })).status, 401);
  }
  const replayedAuthorizationEvent = await submitProviderSecurityEvent(validAuthorizationEvent);
  assert.equal(replayedAuthorizationEvent.status, 200);
  assert.deepEqual(await replayedAuthorizationEvent.json(), { ok: true, replayed: true, revoked: 0 });

  const setThenLogoutReplay = await submitBackchannelToken(await createLogoutToken({
    claims: { sid: "sid-test-owner", sub: "test-owner" },
    jti: "provider-authorization-change-1",
  }));
  assert.equal(setThenLogoutReplay.status, 200);
  assert.deepEqual(await setThenLogoutReplay.json(), { ok: true, replayed: true, revoked: 0 });
  assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie: ownerCookie, accept: "application/json" } })).status, 200);

  const accountDisabledState = await beginLogin();
  const accountDisabledLogin = await fetch(`${baseUrl}/auth/callback?code=account-disabled-owner&state=${encodeURIComponent(accountDisabledState)}`, { redirect: "manual" });
  assert.equal(accountDisabledLogin.status, 303);
  const accountDisabledCookie = cookieHeader(responseSetCookies(accountDisabledLogin));
  const crossTypeReplay = await createProviderSecurityEventToken({
    eventType: "urn:platform-infrastructure:event:account-disabled",
    claims: { sub: "test-account-disabled-owner" },
    jti: "logout-backchannel-owner-1",
  });
  const crossTypeReplayResponse = await submitProviderSecurityEvent(crossTypeReplay);
  assert.equal(crossTypeReplayResponse.status, 200);
  assert.deepEqual(await crossTypeReplayResponse.json(), { ok: true, replayed: true, revoked: 0 });
  assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie: accountDisabledCookie, accept: "application/json" } })).status, 200);
  const setThenSetReplayResponse = await submitProviderSecurityEvent(await createProviderSecurityEventToken({
    eventType: "urn:platform-infrastructure:event:account-disabled",
    claims: { sub: "test-account-disabled-owner" },
    jti: "provider-authorization-change-1",
  }));
  assert.equal(setThenSetReplayResponse.status, 200);
  assert.deepEqual(await setThenSetReplayResponse.json(), { ok: true, replayed: true, revoked: 0 });
  assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie: accountDisabledCookie, accept: "application/json" } })).status, 200);
  const accountDisabledEvent = await createProviderSecurityEventToken({
    eventType: "urn:platform-infrastructure:event:account-disabled",
    claims: { sub: "test-account-disabled-owner" },
    jti: "provider-account-disabled-1",
  });
  const accountDisabledResponse = await submitProviderSecurityEvent(accountDisabledEvent);
  assert.equal(accountDisabledResponse.status, 200);
  assert.deepEqual(await accountDisabledResponse.json(), { ok: true, replayed: false, revoked: 1 });
  assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie: accountDisabledCookie, accept: "application/json" } })).status, 401);

  const auditFailureToken = await createLogoutToken({
    jti: "logout-audit-failure-owner-1",
    claims: { sid: "sid-audit-failure-owner", sub: "test-audit-failure-owner" },
  });
  const providerAuditFailureState = await beginLogin();
  const providerAuditFailureLogin = await fetch(`${baseUrl}/auth/callback?code=provider-audit-failure-owner&state=${encodeURIComponent(providerAuditFailureState)}`, { redirect: "manual" });
  assert.equal(providerAuditFailureLogin.status, 303);
  const providerAuditFailureCookie = cookieHeader(responseSetCookies(providerAuditFailureLogin));
  const providerAuditFailureToken = await createProviderSecurityEventToken({
    eventType: "urn:platform-infrastructure:event:account-disabled",
    claims: { sub: "test-provider-audit-failure-owner" },
    jti: "provider-audit-failure-owner-1",
  });
  const beforeAuditFailure = await fetch(`${baseUrl}/control/overview`, { headers: { cookie: auditFailureCookie, accept: "application/json" } });
  assert.equal(beforeAuditFailure.status, 200);
  assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie: providerAuditFailureCookie, accept: "application/json" } })).status, 200);
  rmSync(auditFile, { force: true });
  mkdirSync(auditFile);
  const committedWithoutAudit = await submitBackchannelToken(auditFailureToken);
  assert.equal(committedWithoutAudit.status, 503);
  assert.equal((await committedWithoutAudit.json()).error, "oidc_backchannel_logout_audit_unavailable");
  const revokedDespiteAuditFailure = await fetch(`${baseUrl}/control/overview`, { headers: { cookie: auditFailureCookie, accept: "application/json" } });
  assert.equal(revokedDespiteAuditFailure.status, 401);
  const providerCommittedWithoutAudit = await submitProviderSecurityEvent(providerAuditFailureToken);
  assert.equal(providerCommittedWithoutAudit.status, 503);
  assert.equal((await providerCommittedWithoutAudit.json()).error, "oidc_provider_security_event_audit_unavailable");
  assert.equal((await fetch(`${baseUrl}/control/overview`, { headers: { cookie: providerAuditFailureCookie, accept: "application/json" } })).status, 401);
  rmSync(auditFile, { recursive: true, force: true });
  const retryAfterAuditRecovery = await submitBackchannelToken(auditFailureToken);
  assert.equal(retryAfterAuditRecovery.status, 200);
  assert.deepEqual(await retryAfterAuditRecovery.json(), { ok: true, replayed: true, revoked: 0 });
  const providerRetryAfterAuditRecovery = await submitProviderSecurityEvent(providerAuditFailureToken);
  assert.equal(providerRetryAfterAuditRecovery.status, 200);
  assert.deepEqual(await providerRetryAfterAuditRecovery.json(), { ok: true, replayed: true, revoked: 0 });

  await beginLogin();
  await beginLogin();
  const throttled = await fetch(`${baseUrl}/auth/login`, { redirect: "manual" });
  assert.equal(throttled.status, 429);

  const logout = await fetch(`${baseUrl}/logout`, {
    method: "POST",
    headers: { cookie: ownerCookie, origin: "https://portal.example.test", "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded", "x-csrf-token": ownerCsrf },
    body: new URLSearchParams({ _csrf: ownerCsrf }),
    redirect: "manual",
  });
  assert.equal(logout.status, 303);
  assert.equal(responseSetCookies(logout).filter((cookie) => /Max-Age=0/.test(cookie)).length, 2);
  const revokedReplay = await fetch(`${baseUrl}/control/overview`, { headers: { cookie: ownerCookie, accept: "application/json" } });
  assert.equal(revokedReplay.status, 401);

  assert.equal(stderr, "");
});

test("OIDC back-channel logout reports transient JWKS failures as retryable", async (t) => {
  const isolatedRoot = path.join(infraRoot, ".tmp", "control-center-tests", `backchannel-jwks-${randomUUID()}`);
  const stateDir = path.join(isolatedRoot, "state");
  const projectsDir = path.join(isolatedRoot, "projects");
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(projectsDir, { recursive: true });

  const idpPort = await freePort();
  const idp = createHttpServer((req, res) => {
    if (req.url === "/jwks") {
      res.writeHead(503, { "content-type": "application/json" });
      res.end('{"error":"temporarily-unavailable"}');
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => idp.listen(idpPort, "127.0.0.1", resolve));

  const port = await freePort();
  const issuer = "https://identity.example.test/realms/platform";
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_ENV: "test",
      CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
      CONTROL_CENTER_AUTH_STORE: "memory",
      CONTROL_CENTER_OIDC_ISSUER: issuer,
      CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: `${issuer}/protocol/openid-connect/auth`,
      CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: `http://127.0.0.1:${idpPort}/token`,
      CONTROL_CENTER_OIDC_JWKS_URI: `http://127.0.0.1:${idpPort}/jwks`,
      CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
      CONTROL_CENTER_OIDC_CLIENT_ID: "platform-control-center",
      CONTROL_CENTER_OIDC_REQUIRED_ACR: "urn:platform:loa:passkey",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      PROJECTS_ROOT: projectsDir,
      ...isolatedStateEnv(stateDir),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  t.after(async () => {
    await stopChild(child);
    await new Promise((resolve) => idp.close(resolve));
    rmSync(isolatedRoot, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHealth(`${baseUrl}/__health`, child);
  const { privateKey } = await generateKeyPair("RS256");
  const logoutToken = await new SignJWT({
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    sid: "transient-jwks-session",
  })
    .setProtectedHeader({ alg: "RS256", kid: "unavailable-key" })
    .setIssuer(issuer)
    .setAudience("platform-control-center")
    .setJti("transient-jwks-1")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);
  const response = await fetch(`${baseUrl}/auth/backchannel-logout`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ logout_token: logoutToken }),
  });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, "oidc_backchannel_logout_unavailable");
  assert.equal(stderr, "");
});

test("OIDC back-channel logout distinguishes JWKS rotation cooldown from an unknown key", async (t) => {
  const isolatedRoot = path.join(infraRoot, ".tmp", "control-center-tests", `backchannel-jwks-rotation-${randomUUID()}`);
  const stateDir = path.join(isolatedRoot, "state");
  const projectsDir = path.join(isolatedRoot, "projects");
  const clockOffsetFile = path.join(isolatedRoot, "clock-offset-ms");
  const clockModule = path.join(isolatedRoot, "clock.mjs");
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(projectsDir, { recursive: true });
  writeFileSync(clockOffsetFile, "0\n");
  writeFileSync(clockModule, [
    'import { readFileSync } from "node:fs";',
    "const realNow = Date.now.bind(Date);",
    "const offsetFile = process.env.CONTROL_CENTER_TEST_CLOCK_OFFSET_FILE;",
    'Date.now = () => realNow() + Number(readFileSync(offsetFile, "utf8").trim() || "0");',
    "",
  ].join("\n"));

  const issuer = "https://identity.example.test/realms/platform";
  const clientId = "platform-control-center";
  const keyA = await generateKeyPair("RS256", { extractable: true });
  const keyB = await generateKeyPair("RS256", { extractable: true });
  const keyC = await generateKeyPair("RS256");
  const jwkA = { ...(await exportJWK(keyA.publicKey)), alg: "RS256", use: "sig", kid: "rotation-key-a" };
  const jwkB = { ...(await exportJWK(keyB.publicKey)), alg: "RS256", use: "sig", kid: "rotation-key-b" };
  let currentJwks = [jwkA];
  let jwksRequests = 0;

  const idpPort = await freePort();
  const idp = createHttpServer((req, res) => {
    if (req.url === "/jwks") {
      jwksRequests += 1;
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(JSON.stringify({ keys: currentJwks }));
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => idp.listen(idpPort, "127.0.0.1", resolve));

  const port = await freePort();
  const child = spawn(process.execPath, ["--import", clockModule, path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      NODE_ENV: "test",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_ENV: "test",
      CONTROL_CENTER_AUTH_MODE: "oidc-passkey",
      CONTROL_CENTER_AUTH_STORE: "memory",
      CONTROL_CENTER_OIDC_ISSUER: issuer,
      CONTROL_CENTER_OIDC_AUTHORIZATION_ENDPOINT: `${issuer}/protocol/openid-connect/auth`,
      CONTROL_CENTER_OIDC_TOKEN_ENDPOINT: `http://127.0.0.1:${idpPort}/token`,
      CONTROL_CENTER_OIDC_JWKS_URI: `http://127.0.0.1:${idpPort}/jwks`,
      CONTROL_CENTER_OIDC_REDIRECT_URI: "https://portal.example.test/auth/callback",
      CONTROL_CENTER_OIDC_CLIENT_ID: clientId,
      CONTROL_CENTER_OIDC_REQUIRED_ACR: "urn:platform:loa:passkey",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      CONTROL_CENTER_TEST_CLOCK_OFFSET_FILE: clockOffsetFile,
      PROJECTS_ROOT: projectsDir,
      ...isolatedStateEnv(stateDir),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  t.after(async () => {
    await stopChild(child);
    await new Promise((resolve) => idp.close(resolve));
    rmSync(isolatedRoot, { recursive: true, force: true });
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForHealth(`${baseUrl}/__health`, child);

  async function logoutToken(privateKey, kid, jti) {
    return new SignJWT({
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
      sid: `sid-${jti}`,
    })
      .setProtectedHeader({ alg: "RS256", kid })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setJti(jti)
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
  }

  async function submit(token) {
    const response = await fetch(`${baseUrl}/auth/backchannel-logout`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ logout_token: token }),
    });
    return { status: response.status, body: await response.json() };
  }

  const tokenA = await logoutToken(keyA.privateKey, "rotation-key-a", "rotation-a");
  assert.deepEqual(await submit(tokenA), {
    status: 200,
    body: { ok: true, replayed: false, revoked: 0 },
  });
  assert.equal(jwksRequests, 1);

  currentJwks = [jwkB];
  const tokenB = await logoutToken(keyB.privateKey, "rotation-key-b", "rotation-b");
  assert.deepEqual(await submit(tokenB), {
    status: 503,
    body: {
      error: "oidc_backchannel_logout_unavailable",
      message: "OIDC back-channel logout is temporarily unavailable; retry safely.",
    },
  });
  assert.equal(jwksRequests, 1, "the remote JWKS must not be fetched during jose's cooldown");

  writeFileSync(clockOffsetFile, "31000\n");
  assert.deepEqual(await submit(tokenB), {
    status: 200,
    body: { ok: true, replayed: false, revoked: 0 },
  });
  assert.equal(jwksRequests, 2, "the rotated key must be fetched after cooldown");

  writeFileSync(clockOffsetFile, "62000\n");
  const unknownToken = await logoutToken(keyC.privateKey, "rotation-key-c", "rotation-c");
  assert.deepEqual(await submit(unknownToken), {
    status: 400,
    body: {
      error: "oidc_backchannel_logout_rejected",
      message: "OIDC back-channel logout was rejected.",
    },
  });
  assert.equal(jwksRequests, 3, "an unknown kid is rejected only after one post-cooldown refresh");
  assert.equal(stderr, "");
});

test("Control Center production startup fails closed without OIDC configuration", async () => {
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      NODE_ENV: "production",
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_BIND_HOST: "127.0.0.1",
      CONTROL_CENTER_ENV: "production",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  const exitCode = await new Promise((resolve) => child.once("exit", resolve));
  assert.notEqual(exitCode, 0);
  assert.match(stderr, /CONTROL_CENTER_AUTH_MODE must be oidc-passkey/);
});

function prepareFixture() {
  rmSync(testRoot, { recursive: true, force: true });
  mkdirSync(path.join(projectsRoot, "php-demo", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "node-demo"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "node-demo", "src"), { recursive: true });
  mkdirSync(path.join(backupsRoot, "postgres"), { recursive: true });
  mkdirSync(path.join(backupsRoot, "mariadb"), { recursive: true });
  mkdirSync(path.join(backupsRoot, "applications", "node-demo"), { recursive: true });
  mkdirSync(path.join(backupsRoot, "manifests"), { recursive: true });
  mkdirSync(path.join(reportsRoot, "backup-jobs"), { recursive: true });
  mkdirSync(path.join(reportsRoot, "offsite-backups"), { recursive: true });
  mkdirSync(path.join(existingSecretsDir, "rclone"), { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(path.join(projectsRoot, "php-demo", "public", "index.php"), "<?php echo 'php-demo';\n");
  writeFileSync(path.join(projectsRoot, "node-demo", "package.json"), `${JSON.stringify({ scripts: { start: "node server.js" } }, null, 2)}\n`);
  writeFileSync(path.join(projectsRoot, "node-demo", "src", "index.js"), "console.log('node-demo');\n");
  writeFileSync(path.join(projectsRoot, "node-demo", ".env"), "DB_NAME=\"node_demo_external\"\nDB_PASSWORD=\"db-password-should-not-leak\"\n");
  writeFileSync(vaultKeyFile, `v20260629000000=${"a".repeat(64)}\n`, { mode: 0o600 });
  writeFileSync(path.join(backupsRoot, "postgres", "node-demo-20260629.dump"), "fixture-backup-data\n");
  writeFileSync(path.join(backupsRoot, "postgres", "node-demo-20260629.sql.gz"), "COPY secrets FROM stdin;\ncopy-row-secret-should-not-leak\n\\.\n");
  writeFileSync(path.join(backupsRoot, "postgres", "node-demo-20260629.dump.sha256"), "fixture-sha256\n");
  writeFileSync(path.join(backupsRoot, "postgres", "preview.txt"), "token=backup-secret-should-not-leak\nhealthy=true\n");
  writeFileSync(path.join(backupsRoot, "applications", "node-demo", "node-demo-source-20260629.tar.gz"), "fixture-source-archive\n");
  writeFileSync(path.join(backupsRoot, "mariadb", "node-demo-20260629.sql.gz"), "fixture-mariadb-backup\n");
  writeFileSync(path.join(backupsRoot, "mariadb", "node-demo-app-delete.sql.gz"), "fixture-managed-mariadb-backup\n");
  writeFileSync(path.join(existingSecretsDir, "github_token.txt"), "existing-github-token-should-reveal-only\n", { mode: 0o600 });
  writeFileSync(path.join(existingSecretsDir, "long_provider_secret.txt"), `${longExistingVaultValue}\n`, { mode: 0o600 });
  writeFileSync(path.join(existingSecretsDir, "rclone", "rclone.conf"), "[onedrive]\ntoken = existing-rclone-token-should-reveal-only\n", { mode: 0o600 });
  writeFileSync(path.join(existingSecretsDir, "README.md"), "not imported\n");
  const dockerStatsCapturedAtEpoch = Math.floor(Date.now() / 1000);
  writeFileSync(dockerStatsFile, `${JSON.stringify({
    schemaVersion: 2,
    capturedAt: new Date(dockerStatsCapturedAtEpoch * 1000).toISOString(),
    capturedAtEpoch: dockerStatsCapturedAtEpoch,
    source: "docker stats --no-stream + docker inspect",
    collector: {
      healthy: true,
      expectedRunning: 2,
      observed: 2,
      missingRunningContainerIds: [],
    },
    containers: [
      { name: "php-php-demo", service: "php-demo", status: "running", cpuPercent: 0, cpuCores: 0, memoryUsageBytes: 25165824, cpuLimitCores: null, memoryLimitBytes: null, memoryReservationBytes: null, pidsLimit: 512 },
      { name: "node-demo", service: "node-demo", status: "running", cpuPercent: 3.5, cpuCores: 0.035, memoryUsageBytes: 100663296, cpuLimitCores: 2, memoryLimitBytes: 536870912, memoryReservationBytes: 268435456, pidsLimit: 256 },
    ],
  }, null, 2)}\n`);
  writeFileSync(databasesFile, `${JSON.stringify({
    "legacy-mariadb-node-demo-external": {
      id: "legacy-mariadb-node-demo-external",
      projectId: "legacy-owner",
      engine: "mariadb",
      name: "node_demo_external",
      ownerRole: "node_demo_user",
      status: "declared",
      linkedApps: ["node-demo"],
    },
    "legacy-postgres-node-demo-external": {
      id: "legacy-postgres-node-demo-external",
      projectId: "legacy-owner",
      engine: "postgres",
      name: "node_demo_pg",
      ownerRole: "node_demo_pg_user",
      status: "declared",
      linkedApps: ["node-demo"],
    },
  }, null, 2)}\n`);
  writeBackupManifestFixture("manifest-node-demo", { kind: "application", id: "node-demo" });
  writeBackupManifestFixture("manifest-platform", { kind: "platform", id: "platform" });
}

function writeBackupManifestFixture(id, scope) {
  const createdAt = new Date(Date.now() - 60_000).toISOString();
  const resourceFixtures = [
    {
      resource: {
        id: backupResourceId("source", "node-demo"),
        externalId: "node-demo",
        kind: "source",
        projectId: "node-demo",
        name: "node-demo",
        sourceDirectory: "node-demo",
      },
      path: "applications/node-demo/node-demo-source-20260629.tar.gz",
    },
    {
      resource: {
        id: backupResourceId("database", "legacy-postgres-node-demo-external"),
        externalId: "legacy-postgres-node-demo-external",
        kind: "database",
        projectId: "node-demo",
        name: "node_demo_pg",
        engine: "postgres",
      },
      path: "postgres/node-demo-20260629.dump",
    },
    {
      resource: {
        id: backupResourceId("database", "legacy-mariadb-node-demo-external"),
        externalId: "legacy-mariadb-node-demo-external",
        kind: "database",
        projectId: "node-demo",
        name: "node_demo_external",
        engine: "mariadb",
      },
      path: "mariadb/node-demo-20260629.sql.gz",
    },
    {
      resource: {
        id: backupResourceId("database", "node-demo-mariadb-node-demo-app"),
        externalId: "node-demo-mariadb-node-demo-app",
        kind: "database",
        projectId: "node-demo",
        name: "node_demo_app",
        engine: "mariadb",
      },
      path: "mariadb/node-demo-app-delete.sql.gz",
    },
  ];
  const job = createBackupJobDocument({
    id: `job-${id}`,
    operation: "backup",
    scope,
    resources: resourceFixtures.map((item) => item.resource),
    requestedBy: "fixture",
    environment: "test",
    createdAt,
  });
  const manifest = createBackupManifestDocument({
    id,
    job,
    createdAt,
    artifacts: resourceFixtures.map(({ resource, path: artifactPath }, index) => {
      const absolutePath = path.join(backupsRoot, artifactPath);
      const content = readFileSync(absolutePath);
      const hash = createHash("sha256").update(content).digest("hex");
      writeFileSync(`${absolutePath}.sha256`, `${hash}  ${path.basename(absolutePath)}\n`, { mode: 0o600 });
      writeFileSync(`${absolutePath}.sig.json`, `${JSON.stringify({ algorithm: "HMAC-SHA256", keyId: "fixture-key-v1", hash, signature: "fixture-signature" })}\n`, { mode: 0o600 });
      return {
        id: `artifact-${id}-${index}`,
        resourceId: resource.id,
        path: artifactPath,
        sha256: hash,
        sizeBytes: content.length,
        signatureKeyId: "fixture-key-v1",
      };
    }),
  });
  const signed = {
    ...manifest,
    signature: {
      algorithm: "HMAC-SHA256",
      keyId: "fixture-key-v1",
      digest: backupDocumentDigest(manifest),
      value: "Zml4dHVyZS1zaWduYXR1cmU",
    },
  };
  const manifestPath = `manifests/${id}.json`;
  writeFileSync(path.join(backupsRoot, manifestPath), `${JSON.stringify(signed, null, 2)}\n`, { mode: 0o600 });
  const resourceIds = resourceFixtures.map(({ resource }) => resource.id);
  const restoreFinishedAt = new Date(Date.parse(createdAt) + 10_000).toISOString();
  writeFileSync(path.join(reportsRoot, "backup-jobs", `restore-${id}.json`), `${JSON.stringify({
    status: "passed",
    operation: "restore-drill",
    jobId: `restore-${id}`,
    manifestPath,
    resourceIds,
    results: resourceIds.map((resourceId) => ({ resourceId, status: "passed" })),
    liveDataChanged: false,
    finishedAt: restoreFinishedAt,
  }, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(path.join(reportsRoot, "offsite-backups", `offsite-${id}.json`), `${JSON.stringify({
    schema: "platform.offsite-backup-receipt/v1",
    status: "passed",
    manifestId: signed.id,
    manifestPath,
    manifestDigest: signed.signature.digest,
    resourceIds,
    snapshotId: `snapshot-${id}`,
    hostname: "platform-infrastructure",
    repositoryOffsite: true,
    finishedAt: new Date(Date.parse(createdAt) + 20_000).toISOString(),
  }, null, 2)}\n`, { mode: 0o600 });
}

function isolatedStateEnv(stateRoot) {
  return {
    PROJECT_STATE_FILE: path.join(stateRoot, "projects.json"),
    PROJECT_AUDIT_FILE: path.join(stateRoot, "audit.jsonl"),
    PROJECT_OPERATIONS_FILE: path.join(stateRoot, "operations.jsonl"),
    PROJECT_APPLICATIONS_FILE: path.join(stateRoot, "applications.json"),
    PROJECT_DOMAINS_FILE: path.join(stateRoot, "domains.json"),
    PROJECT_DATABASES_FILE: path.join(stateRoot, "databases.json"),
    PROJECT_DATABASE_PRINCIPALS_FILE: path.join(stateRoot, "database-principals.json"),
    PROJECT_DATABASE_DESTRUCTIVE_OPERATIONS_FILE: path.join(stateRoot, "database-destructive-operations.json"),
    PROJECT_STORAGE_BUCKETS_FILE: path.join(stateRoot, "storage-buckets.json"),
    PROJECT_SENSITIVE_MATERIALS_FILE: path.join(stateRoot, "sensitive-materials.json"),
    PROJECT_VAULT_FILE: path.join(stateRoot, "secret-vault.json"),
    CONTROL_CENTER_VAULT_KEY_FILE: path.join(stateRoot, "vault.key"),
    CONTROL_CENTER_EXISTING_SECRETS_DIR: path.join(stateRoot, "existing-secrets"),
    PROJECT_WORKER_JOBS_FILE: path.join(stateRoot, "worker-jobs.json"),
    PROJECT_IDENTITY_ACCESS_FILE: path.join(stateRoot, "identity-access.json"),
    PROJECT_DEPLOYMENTS_FILE: path.join(stateRoot, "deployments.jsonl"),
    PROJECT_BACKUP_RECORDS_FILE: path.join(stateRoot, "backups.jsonl"),
    PROJECT_BACKUP_JOBS_DIR: path.join(stateRoot, "backup-jobs"),
    PROJECT_RESOURCE_LIMITS_FILE: path.join(stateRoot, "resource-limits.json"),
    PROJECT_SECURITY_POLICIES_FILE: path.join(stateRoot, "security-policies.json"),
    PROJECT_ALERTS_FILE: path.join(stateRoot, "alerts.json"),
    PROJECT_NOTIFICATION_CHANNELS_FILE: path.join(stateRoot, "notification-channels.json"),
    PROJECT_PROVIDER_CONNECTIONS_FILE: path.join(stateRoot, "provider-connections.json"),
    PROJECT_SETTINGS_FILE: path.join(stateRoot, "settings.json"),
    PROJECT_WEBSPACES_FILE: path.join(stateRoot, "webspaces.json"),
    PROJECT_STATUS_RUNS_FILE: path.join(stateRoot, "status-runs.jsonl"),
    PROJECT_STATUS_RUN_EVENTS_FILE: path.join(stateRoot, "status-run-events.jsonl"),
    CONTROL_CENTER_STATUS_STEP_DELAY_MS: "0",
  };
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

async function waitForHealth(url, child) {
  const started = Date.now();
  while (Date.now() - started < 10000) {
    if (child.exitCode !== null) {
      throw new Error(`Control Center exited early with code ${child.exitCode}.`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Retry until the child server has started listening.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Timed out waiting for Control Center health endpoint.");
}

async function stopChild(child) {
  if (child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 3000)),
  ]);
  if (child.exitCode === null) {
    child.kill("SIGKILL");
    await Promise.race([
      new Promise((resolve) => child.once("exit", resolve)),
      new Promise((resolve) => setTimeout(resolve, 1000)),
    ]);
  }
}

function responseSetCookies(response) {
  if (typeof response.headers.getSetCookie === "function") return response.headers.getSetCookie();
  const combined = response.headers.get("set-cookie") || "";
  return combined ? combined.split(/,\s*(?=__Host-)/) : [];
}

function cookieHeader(setCookies) {
  return setCookies.map((cookie) => cookie.split(";", 1)[0]).join("; ");
}

function cookieValue(setCookies, name) {
  const prefix = `${name}=`;
  const match = setCookies.map((cookie) => cookie.split(";", 1)[0]).find((cookie) => cookie.startsWith(prefix));
  return match ? match.slice(prefix.length) : "";
}

async function getJson(url, init = {}) {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(`${url} returned ${response.status}: ${await response.text()}`);
  return response.json();
}

async function getText(url, init = {}) {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(`${url} returned ${response.status}: ${await response.text()}`);
  return response.text();
}

async function getTextWithHost(url, host) {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      method: "GET",
      headers: { Host: host },
    }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        try {
          assert.equal(res.statusCode && res.statusCode >= 200 && res.statusCode < 300, true, `${url} returned ${res.statusCode}`);
          resolve(body);
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on("error", reject);
    req.end();
  });
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let parsed;
  try {
    parsed = await response.json();
  } catch {
    parsed = {};
  }
  return { status: response.status, body: parsed };
}
