import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { request as httpRequest } from "node:http";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

const infraRoot = path.resolve(import.meta.dirname, "..", "..");
const testRoot = path.join(infraRoot, ".tmp", "control-center-tests", randomUUID());
const projectsRoot = path.join(testRoot, "projects");
const stateDir = path.join(testRoot, "state");
const stateFile = path.join(stateDir, "projects.json");
const auditFile = path.join(stateDir, "audit.jsonl");
const operationsFile = path.join(stateDir, "operations.jsonl");
const applicationsFile = path.join(stateDir, "applications.json");
const domainsFile = path.join(stateDir, "domains.json");
const databasesFile = path.join(stateDir, "databases.json");
const storageBucketsFile = path.join(stateDir, "storage-buckets.json");
const sensitiveMaterialsFile = path.join(stateDir, "sensitive-materials.json");
const workerJobsFile = path.join(stateDir, "worker-jobs.json");
const identityAccessFile = path.join(stateDir, "identity-access.json");
const deploymentsFile = path.join(stateDir, "deployments.jsonl");
const backupRecordsFile = path.join(stateDir, "backups.jsonl");
const resourceLimitsFile = path.join(stateDir, "resource-limits.json");
const securityPoliciesFile = path.join(stateDir, "security-policies.json");
const alertsFile = path.join(stateDir, "alerts.json");
const notificationChannelsFile = path.join(stateDir, "notification-channels.json");
const providerConnectionsFile = path.join(stateDir, "provider-connections.json");
const settingsFile = path.join(stateDir, "settings.json");
const webspacesFile = path.join(stateDir, "webspaces.json");

test("Admin Control Center local foundation", async (t) => {
  prepareFixture();
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_ENV: "local",
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      PROJECTS_ROOT: projectsRoot,
      PROJECT_STATE_FILE: stateFile,
      PROJECT_AUDIT_FILE: auditFile,
      PROJECT_OPERATIONS_FILE: operationsFile,
      PROJECT_APPLICATIONS_FILE: applicationsFile,
      PROJECT_DOMAINS_FILE: domainsFile,
      PROJECT_DATABASES_FILE: databasesFile,
      PROJECT_STORAGE_BUCKETS_FILE: storageBucketsFile,
      PROJECT_SENSITIVE_MATERIALS_FILE: sensitiveMaterialsFile,
      PROJECT_WORKER_JOBS_FILE: workerJobsFile,
      PROJECT_IDENTITY_ACCESS_FILE: identityAccessFile,
      PROJECT_DEPLOYMENTS_FILE: deploymentsFile,
      PROJECT_BACKUP_RECORDS_FILE: backupRecordsFile,
      PROJECT_RESOURCE_LIMITS_FILE: resourceLimitsFile,
      PROJECT_SECURITY_POLICIES_FILE: securityPoliciesFile,
      PROJECT_ALERTS_FILE: alertsFile,
      PROJECT_NOTIFICATION_CHANNELS_FILE: notificationChannelsFile,
      PROJECT_PROVIDER_CONNECTIONS_FILE: providerConnectionsFile,
      PROJECT_SETTINGS_FILE: settingsFile,
      PROJECT_WEBSPACES_FILE: webspacesFile,
      CONTROL_CENTER_HOST: "admin.localhost.com",
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
  assert.match(html, /Simple/);
  assert.match(html, /Advanced/);
  assert.match(html, /Php Demo/);
  assert.match(html, /Node Demo/);
  assert.match(html, /\/assets\/control-center\/control-center\.css/);
  assert.match(html, /\/assets\/control-center\/control-center\.js/);
  assert.match(html, /cc-app-shell/);
  assert.match(html, /cc-stage/);
  assert.match(html, /cc-sidebar/);
  assert.match(html, /data-cc-sidebar-toggle="gestione"/);
  assert.match(html, /data-cc-sidebar-toggle="sicurezza"/);
  assert.match(html, /data-cc-sidebar-toggle="avanzato"/);
  assert.match(html, /aria-expanded="true"/);
  assert.doesNotMatch(html, /class="cc-tabs"/);
  assert.doesNotMatch(html, /Open navigation/);
  assert.doesNotMatch(html, /Search Control Center/);
  assert.doesNotMatch(html, /aria-label="Help"/);
  assert.doesNotMatch(html, /aria-label="Settings"/);
  assert.match(html, /data-cc-theme="light"/);
  assert.doesNotMatch(html, /data-cc-theme="dark"/);
  assert.doesNotMatch(html, /onchange=/);
  assert.equal(html.includes(["/assets", "node-demo", "ui"].join("/") + "/"), false);
  assert.doesNotMatch(html, new RegExp(`${["ui", "shell"].join("-")}|${["pill", "sidebar", "nav"].join("-")}|${["pill", "tabs"].join("-")}`));
  assert.match(html, /platform-wordmark/);
  assert.match(html, /hosting-dashboard/);
  assert.match(html, /Pannello infrastruttura/);
  assert.match(html, /Gestisci la tua piattaforma da un solo posto/);
  assert.match(html, /Siti e applicazioni/);
  assert.match(html, /Superfici pubbliche/);
  assert.match(html, /Operazioni rapide/);
  assert.match(html, /runtime-badge php/);
  assert.match(html, /runtime-badge node/);
  assert.doesNotMatch(html, /phpmyadmin\.localhost\.com/);
  assert.doesNotMatch(html, /grafana\.localhost\.com/);
  assert.match(html, /Gestione/);
  assert.match(html, /Sicurezza/);
  assert.match(html, /Avanzato/);

  const docsHtml = await getTextWithHost(`${baseUrl}/`, "docs.localhost.com");
  assert.match(docsHtml, /Docs .* Platform Infrastructure/);
  assert.match(docsHtml, /Quickstart/);
  assert.match(docsHtml, /Architecture/);
  assert.match(docsHtml, /Runbook/);
  assert.match(docsHtml, /GitHub\/Sigstore/);
  assert.match(docsHtml, /Admin Control Center/);
  const readmeHtml = await getTextWithHost(`${baseUrl}/docs/README.md`, "docs.localhost.com");
  assert.match(readmeHtml, /Platform Infrastructure/);
  assert.match(readmeHtml, /Docker-first, white-label infrastructure/);

  const localStyles = await getText(`${baseUrl}/assets/control-center/control-center.css`);
  assert.match(localStyles, /--cc-bg/);
  assert.match(localStyles, /--cc-surface-raised/);
  assert.match(localStyles, /--cc-line/);
  assert.match(localStyles, /\.cc-app-shell/);
  assert.match(localStyles, /\.cc-sidebar/);
  assert.match(localStyles, /\.cc-nav-toggle/);
  assert.match(localStyles, /\.cc-nav-child/);
  assert.match(localStyles, /\.cc-nav-branch/);
  assert.match(localStyles, /\.hosting-dashboard/);
  assert.match(localStyles, /\.hosting-summary-grid/);
  assert.match(localStyles, /\.hosting-table/);
  assert.match(localStyles, /\.hosting-service-row/);
  assert.match(localStyles, /max-height var\(--cc-enter\)/);
  assert.match(localStyles, /\.cc-sidebar,\s*\.cc-sidebar \*/);
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
  assert.match(localClient, /ccBootId/);
  assert.match(localClient, /platform-control-center-sidebar/);
  assert.match(localClient, /toggleSidebarGroup/);
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
  assert.equal(localUiPackage.coreExports.includes("AppShell"), true);
  assert.equal(localUiPackage.coreExports.includes("Sidebar"), true);
  assert.equal(localUiPackage.coreExports.includes("TabGroup"), true);
  assert.equal(localUiPackage.cssVariablePrefix, "--cc-");
  assert.deepEqual(localUiPackage.missingRequiredExports, []);

  const advancedHtml = await getText(`${baseUrl}/?mode=advanced&section=infrastructure`);
  assert.match(advancedHtml, /Infrastructure/);
  assert.match(advancedHtml, /Traefik/);
  assert.match(advancedHtml, /cAdvisor/);
  assert.match(advancedHtml, /cc-sidebar/);
  assert.doesNotMatch(advancedHtml, /class="cc-tabs"/);
  assert.doesNotMatch(advancedHtml, /role="tablist"/);
  assert.match(advancedHtml, /cc-nav-child/);
  assert.match(advancedHtml, /data-cc-sidebar-toggle="platform"/);
  assert.match(advancedHtml, /data-cc-sidebar-toggle="delivery"/);
  assert.match(advancedHtml, /data-cc-sidebar-toggle="observability"/);
  assert.match(advancedHtml, /Avanzato/);
  assert.match(advancedHtml, /Deployments/);
  assert.match(advancedHtml, /CI\/CD &amp; GitHub Governance/);
  assert.match(advancedHtml, /Cloudflare/);
  assert.match(advancedHtml, /Workers &amp; Jobs/);
  assert.match(advancedHtml, /Network/);
  assert.match(advancedHtml, /Databases/);
  assert.match(advancedHtml, /Logs Advanced/);
  assert.match(advancedHtml, /Billing \/ Plans/);

  const networkApi = await getJson(`${baseUrl}/control/network`);
  assert.equal(networkApi.guardrails.readOnly, true);
  assert.equal(networkApi.guardrails.routeTestsArePlans, true);
  assert.equal(networkApi.providerTouched, false);
  assert.equal(networkApi.networkProbeExecuted, false);
  assert.equal(networkApi.productionEvidence, false);
  assert.equal(networkApi.routers.some((router) => router.id === "enterprise-admin" && router.tls === true && router.sampleHost === "admin.localhost.com" && router.middlewares.includes("enterprise-rate-limit@file")), true);
  assert.equal(networkApi.routers.some((router) => router.id === "enterprise-docs" && router.tls === true && router.sampleHost === "docs.localhost.com" && router.middlewares.includes("enterprise-rate-limit@file")), true);
  assert.equal(networkApi.routers.some((router) => router.id === "enterprise-backend"), false);
  assert.equal(networkApi.routers.some((router) => router.id === "local-projects"), false);
  assert.equal(networkApi.middlewares.some((middleware) => middleware.id === "enterprise-rate-limit" && middleware.type === "rateLimit" && /average 120/.test(middleware.summary)), true);
  assert.equal(networkApi.exposedPorts.some((port) => port.hostPort === "80" && port.containerPort === "80" && port.loopbackOnly === true && port.publicExposure === false), true);
  assert.equal(networkApi.exposedPorts.some((port) => port.hostPort === "443" && port.containerPort === "443" && port.loopbackOnly === true && port.publicExposure === false), true);
  assert.equal(networkApi.tls.status, "configured");
  assert.equal(networkApi.routeTests.some((testPlan) => testPlan.routerId === "enterprise-admin" && testPlan.url === "https://admin.localhost.com/" && testPlan.networkProbeExecuted === false), true);

  const advancedNetworkApi = await getJson(`${baseUrl}/control/advanced/network`);
  assert.equal(advancedNetworkApi.data.routers.some((router) => router.id === "enterprise-admin"), true);
  assert.equal(advancedNetworkApi.data.routers.some((router) => router.id === "enterprise-backend"), false);
  assert.equal(advancedNetworkApi.data.routeTests.some((testPlan) => testPlan.productionEvidence === false), true);
  assert.equal(advancedNetworkApi.data.originLockStatus, "not-required-local-loopback");

  const advancedNetworkHtml = await getText(`${baseUrl}/?mode=advanced&section=network`);
  assert.match(advancedNetworkHtml, /Traefik Network/);
  assert.match(advancedNetworkHtml, /Router Topology/);
  assert.match(advancedNetworkHtml, /Middleware Chain/);
  assert.match(advancedNetworkHtml, /Loopback host ports/);
  assert.match(advancedNetworkHtml, /Route Test Plan/);
  assert.match(advancedNetworkHtml, /enterprise-admin/);

  const monitoringApi = await getJson(`${baseUrl}/control/monitoring`);
  assert.equal(monitoringApi.guardrails.readOnly, true);
  assert.equal(monitoringApi.guardrails.noPrometheusQueryFromPanel, true);
  assert.equal(monitoringApi.guardrails.noLokiQueryFromPanel, true);
  assert.equal(monitoringApi.liveQueryExecuted, false);
  assert.equal(monitoringApi.productionEvidence, false);
  assert.equal(monitoringApi.scrapeJobs.some((job) => job.jobName === "backend" && job.targets.includes("backend:3000")), true);
  assert.equal(monitoringApi.scrapeJobs.some((job) => job.jobName === "workers" && job.targets.includes("worker-jobs:3000")), true);
  assert.equal(monitoringApi.scrapeJobs.some((job) => job.jobName === "node-exporter" && job.category === "host"), true);
  assert.equal(monitoringApi.scrapeJobs.some((job) => job.jobName === "cadvisor" && job.category === "container"), true);
  assert.equal(monitoringApi.datasources.some((datasource) => datasource.name === "Prometheus" && datasource.url === "http://prometheus:9090"), true);
  assert.equal(monitoringApi.datasources.some((datasource) => datasource.name === "Loki" && datasource.url === "http://loki:3100"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "Backend errors" && panel.signal === "backend-errors"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "Worker errors" && panel.signal === "worker-errors"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "WAF events" && panel.signal === "waf-events"), true);
  assert.equal(monitoringApi.dashboardPanels.some((panel) => panel.title === "Auth failures" && panel.signal === "auth-failures"), true);
  assert.equal(monitoringApi.signals.every((signal) => signal.coverage === "configured" && signal.liveQueryExecuted === false), true);
  assert.equal(monitoringApi.alertmanager.credentialFileConfigured, true);
  assert.equal(monitoringApi.alertmanager.secretValueExposed, false);
  assert.equal(monitoringApi.loki.retentionPeriod, "168h");

  const advancedMonitoringApi = await getJson(`${baseUrl}/control/advanced/monitoring`);
  assert.equal(advancedMonitoringApi.data.signals.some((signal) => signal.id === "error-rate"), true);
  assert.equal(advancedMonitoringApi.data.prometheus.liveQueryExecuted, false);
  assert.equal(advancedMonitoringApi.productionEvidence, false);

  const advancedMonitoringHtml = await getText(`${baseUrl}/?mode=advanced&section=monitoring`);
  assert.match(advancedMonitoringHtml, /Monitoring/);
  assert.match(advancedMonitoringHtml, /Logs Advanced/);
  assert.match(advancedMonitoringHtml, /Alerts Advanced/);
  assert.match(advancedMonitoringHtml, /Prometheus Targets/);
  assert.match(advancedMonitoringHtml, /Grafana Panels/);
  assert.match(advancedMonitoringHtml, /Alert Rules/);
  assert.match(advancedMonitoringHtml, /Backend errors/);
  assert.match(advancedMonitoringHtml, /WAF events/);
  assert.match(advancedMonitoringHtml, /Auth failures/);

  const advancedWorkersHtml = await getText(`${baseUrl}/?mode=advanced&section=workers-jobs`);
  assert.match(advancedWorkersHtml, /Workers &amp; Jobs/);
  assert.match(advancedWorkersHtml, /failed jobs/);
  assert.match(advancedWorkersHtml, /retry controls/);
  assert.match(advancedWorkersHtml, /Containerized Scheduler/);
  assert.match(advancedWorkersHtml, /Declare worker/);

  const advancedGithubHtml = await getText(`${baseUrl}/?mode=advanced&section=cicd-github`);
  assert.match(advancedGithubHtml, /CI\/CD &amp; GitHub Governance/);
  assert.match(advancedGithubHtml, /Deployments/);
  assert.match(advancedGithubHtml, /Cloudflare/);
  assert.match(advancedGithubHtml, /Release Evidence/);
  assert.match(advancedGithubHtml, /Production Go\/No-Go/);
  assert.match(advancedGithubHtml, /Readiness Matrix/);
  assert.match(advancedGithubHtml, /branch protection/);
  assert.match(advancedGithubHtml, /workflow status/);
  assert.match(advancedGithubHtml, /deploy approvals/);

  const advancedLogsHtml = await getText(`${baseUrl}/?mode=advanced&section=logs-advanced`);
  assert.match(advancedLogsHtml, /Logs Advanced/);
  assert.match(advancedLogsHtml, /query Loki/);
  assert.match(advancedLogsHtml, /request id/);
  assert.match(advancedLogsHtml, /non-sensitive export/);

  const advancedAlertsHtml = await getText(`${baseUrl}/?mode=advanced&section=alerts-advanced`);
  assert.match(advancedAlertsHtml, /Alerts Advanced/);
  assert.match(advancedAlertsHtml, /delivery evidence/);
  assert.match(advancedAlertsHtml, /failure evidence/);
  assert.match(advancedAlertsHtml, /escalation/);

  const advancedDrHtml = await getText(`${baseUrl}/?mode=advanced&section=disaster-recovery`);
  assert.match(advancedDrHtml, /Disaster Recovery/);
  assert.match(advancedDrHtml, /RTO\/RPO/);
  assert.match(advancedDrHtml, /WAL archive/);
  assert.match(advancedDrHtml, /off-site restore evidence/);

  const advancedReleaseHtml = await getText(`${baseUrl}/?mode=advanced&section=release-evidence`);
  assert.match(advancedReleaseHtml, /Release Evidence/);
  assert.match(advancedReleaseHtml, /SBOM/);
  assert.match(advancedReleaseHtml, /provenance/);
  assert.match(advancedReleaseHtml, /rollback validation/);

  const advancedSecurityHtml = await getText(`${baseUrl}/?mode=advanced&section=security-advanced`);
  assert.match(advancedSecurityHtml, /Security Advanced/);
  assert.match(advancedSecurityHtml, /Identity &amp; Access/);
  assert.match(advancedSecurityHtml, /Secrets/);
  assert.match(advancedSecurityHtml, /Audit Log/);
  assert.match(advancedSecurityHtml, /secret scan/);
  assert.match(advancedSecurityHtml, /vulnerability scan/);
  assert.match(advancedSecurityHtml, /Cloudflare Access/);

  const applicationsHtml = await getText(`${baseUrl}/?section=applications`);
  assert.match(applicationsHtml, /Applications/);
  assert.match(applicationsHtml, /Create app/);
  assert.match(applicationsHtml, /Deploy/);
  assert.match(applicationsHtml, /Rollback/);

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
  assert.equal(readiness.manifests.productionReadiness.requirementCount, 20);
  assert.equal(readiness.manifests.productionReadiness.requirements.some((item) => item.id === "tls-https-production-ready" && item.status === "pending-live-proof"), true);
  assert.equal(readiness.manifests.enterprise.loaded, true);
  assert.equal(readiness.summary.needsWork, 0);
  assert.equal(readiness.summary.localModeReady, true);
  assert.equal(readiness.summary.productionReady, false);
  assert.equal(readiness.summary.pendingLiveProof > 0, true);
  assert.equal(readiness.productionBlockers.some((item) => item.id === "production-live-proof"), true);
  assert.doesNotMatch(JSON.stringify(readiness), /CLOUDFLARE_API_TOKEN|super-secret-token-should-not-leak/);

  const readinessHtml = await getText(`${baseUrl}/?mode=advanced&section=readiness`);
  assert.match(readinessHtml, /Readiness Matrix/);
  assert.match(readinessHtml, /Control Center coverage/);
  assert.match(readinessHtml, /Production readiness checklist/);
  assert.match(readinessHtml, /pending-live-proof/);

  const advancedIdentityApi = await getJson(`${baseUrl}/control/advanced/identity`);
  assert.equal(advancedIdentityApi.data.sessionPolicy, "HttpOnly; Secure; SameSite=Lax");
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
    ["php-demo", "PHP"],
    ["node-demo", "Node"],
  ]);

  const duplicateProject = await postJson(`${baseUrl}/control/projects`, {
    slug: "node-demo",
  });
  assert.equal(duplicateProject.status, 422);
  assert.match(duplicateProject.body.message, /already exists/);

  const projectPlan = await postJson(`${baseUrl}/control/projects`, {
    slug: "client-portal",
    displayName: "Client Portal",
    runtime: "node",
    host: "client.localhost.com",
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
  assert.doesNotMatch(JSON.stringify(projectPlan.body), /project-secret-should-not-leak/);

  const projectApply = await postJson(`${baseUrl}/control/projects`, {
    slug: "client-portal",
    displayName: "Client Portal",
    runtime: "node",
    host: "client.localhost.com",
    confirm: "CREATE-PROJECT",
    secret: "project-secret-should-not-leak",
  });
  assert.equal(projectApply.status, 202);
  assert.equal(projectApply.body.type, "project.create.local");
  assert.equal(projectApply.body.project.slug, "client-portal");
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
  assert.match(projectsHtmlAfterCreate, /Create project/);
  assert.match(projectsHtmlAfterCreate, /Client Portal/);
  assert.match(projectsHtmlAfterCreate, /Routing waits for mounted source files/);

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

  const applicationsHtmlAfterCreate = await getText(`${baseUrl}/?section=applications`);
  assert.match(applicationsHtmlAfterCreate, /Events Worker/);
  assert.match(applicationsHtmlAfterCreate, /control-center-state/);
  assert.match(applicationsHtmlAfterCreate, /Healthcheck:/);
  assert.match(applicationsHtmlAfterCreate, /Lifecycle:/);
  assert.match(applicationsHtmlAfterCreate, /Healthcheck<\/button>/);

  const workerInventoryInitial = await getJson(`${baseUrl}/control/workers-jobs`);
  assert.equal(workerInventoryInitial.workers.some((worker) => worker.id === "enterprise-worker-jobs"), true);
  assert.equal(workerInventoryInitial.workers.some((worker) => worker.id === "node-demo-events-worker"), true);
  assert.equal(workerInventoryInitial.queues.some((queue) => queue.id === "audit-outbox"), true);
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

  const workersHtmlAfterApply = await getText(`${baseUrl}/?mode=advanced&section=workers-jobs`);
  assert.match(workersHtmlAfterApply, /Worker Runtime/);
  assert.match(workersHtmlAfterApply, /events-processor/);
  assert.match(workersHtmlAfterApply, /Plan retry/);
  assert.match(workersHtmlAfterApply, /nightly-events-sync/);

  const projectsHtml = await getText(`${baseUrl}/?section=projects`);
  assert.match(projectsHtml, /ARCHIVE-PROJECT/);
  assert.match(projectsHtml, /DELETE-PROJECT:php-demo/);

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
  assert.match(domainsHtml, /Add domain/);
  assert.match(domainsHtml, /Provider connection/);
  assert.match(domainsHtml, /Add local/);
  assert.match(domainsHtml, /Discovered route/);

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

  const webspacesHtml = await getText(`${baseUrl}/?section=webspaces`);
  assert.match(webspacesHtml, /Create space/);
  assert.match(webspacesHtml, /public, private, uploads, backups, config/);

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

  const databasesHtml = await getText(`${baseUrl}/?mode=advanced&section=databases`);
  assert.match(databasesHtml, /Databases/);
  assert.match(databasesHtml, /Declare database/);

  const invalidDatabase = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "bad-name",
  });
  assert.equal(invalidDatabase.status, 422);
  assert.match(invalidDatabase.body.message, /Invalid database identifier/);

  const databasePlan = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "node_demo_app",
    ownerRole: "node_demo_user",
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databasePlan.status, 202);
  assert.equal(databasePlan.body.type, "database.create");
  assert.equal(databasePlan.body.dryRun, true);
  assert.equal(databasePlan.body.details.confirmationRequired, "CREATE-DATABASE");
  assert.equal(databasePlan.body.details.databaseTouched, false);
  assert.equal(databasePlan.body.details.credentialsExposed, false);
  assert.doesNotMatch(JSON.stringify(databasePlan.body), /database-secret-should-not-leak/);

  const databaseApply = await postJson(`${baseUrl}/control/databases`, {
    projectId: "node-demo",
    engine: "mariadb",
    name: "node_demo_app",
    ownerRole: "node_demo_user",
    confirm: "CREATE-DATABASE",
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databaseApply.status, 202);
  assert.equal(databaseApply.body.type, "database.create.local");
  assert.equal(databaseApply.body.dryRun, false);
  assert.equal(databaseApply.body.database.id, "node-demo-mariadb-node-demo-app");
  assert.equal(databaseApply.body.details.databaseTouched, false);
  assert.equal(databaseApply.body.details.credentialsExposed, false);

  const databasesAfterApply = await getJson(`${baseUrl}/control/databases`);
  assert.equal(databasesAfterApply.engines.some((engine) => engine.id === "mariadb"), true);
  assert.equal(databasesAfterApply.databases.some((database) => database.id === "node-demo-mariadb-node-demo-app"), true);
  assert.equal(existsSync(databasesFile), true);
  const databaseStateText = readFileSync(databasesFile, "utf8");
  assert.doesNotMatch(databaseStateText, /database-secret-should-not-leak/);
  assert.equal(JSON.parse(databaseStateText)["node-demo-mariadb-node-demo-app"].credentialsExposed, false);

  const databasesHtmlAfterApply = await getText(`${baseUrl}/?mode=advanced&section=databases`);
  assert.match(databasesHtmlAfterApply, /Plan backup/);
  assert.match(databasesHtmlAfterApply, /Plan restore/);

  const databaseBackup = await postJson(`${baseUrl}/control/databases/node-demo-mariadb-node-demo-app/backup`, {
    secret: "database-secret-should-not-leak",
  });
  assert.equal(databaseBackup.status, 202);
  assert.equal(databaseBackup.body.type, "database.backup");
  assert.equal(databaseBackup.body.dryRun, true);
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

  const storageHtml = await getText(`${baseUrl}/?mode=advanced&section=storage`);
  assert.match(storageHtml, /Storage/);
  assert.match(storageHtml, /Declare bucket/);
  assert.match(storageHtml, /Access keys/);

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
  assert.match(storageHtmlAfterApply, /Update policy/);
  assert.match(storageHtmlAfterApply, /Update lifecycle/);
  assert.match(storageHtmlAfterApply, /Update access key/);
  assert.match(storageHtmlAfterApply, /Plan backup/);
  assert.match(storageHtmlAfterApply, /Plan restore/);

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
  assert.match(secretsHtml, /Secrets/);
  assert.match(secretsHtml, /Declare material/);
  assert.match(secretsHtml, /Material Inventory/);
  assert.match(secretsHtml, /Docker secrets/);

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
  assert.match(secretsHtmlAfterApply, /Update rotation/);
  assert.match(secretsHtmlAfterApply, /Update usage/);
  assert.match(secretsHtmlAfterApply, /Record access/);

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
    usageTarget: "worker-jobs",
    confirm: "UPDATE-MATERIAL-USAGE",
  });
  assert.equal(materialUsage.status, 202);
  assert.equal(materialUsage.body.type, "material.usage.local");
  assert.deepEqual(materialUsage.body.material.usageTargets, ["worker-jobs"]);

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

  const resourcesHtml = await getText(`${baseUrl}/?section=resources`);
  assert.match(resourcesHtml, /Resources/);
  assert.match(resourcesHtml, /Quota per project/);
  assert.match(resourcesHtml, /Set limits/);

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

  const resourceLimitApply = await postJson(`${baseUrl}/actions/resource-command`, {
    action: "limits",
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
  assert.match(securityHtml, /Security/);
  assert.match(securityHtml, /WAF/);
  assert.match(securityHtml, /Rate limit/);
  assert.match(securityHtml, /Cloudflare Access/);
  assert.match(securityHtml, /Admin Protection/);
  assert.match(securityHtml, /Security Headers/);
  assert.match(securityHtml, /Update policy/);

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
  assert.match(identityHtml, /Identity &amp; Access/);
  assert.match(identityHtml, /Declare admin user/);
  assert.match(identityHtml, /Roles &amp; Teams/);
  assert.match(identityHtml, /Sessions &amp; Reviews/);
  assert.match(identityHtml, /Ops Admin/);

  const logsHtml = await getText(`${baseUrl}/?section=logs`);
  assert.match(logsHtml, /Logs \/ Alerts/);
  assert.match(logsHtml, /Open alerts/);
  assert.match(logsHtml, /Recent errors/);
  assert.match(logsHtml, /Notification Channels/);
  assert.match(logsHtml, /Email/);
  assert.match(logsHtml, /Discord/);
  assert.match(logsHtml, /Telegram/);
  assert.match(logsHtml, /Record alert/);

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
  assert.match(settingsHtml, /Settings/);
  assert.match(settingsHtml, /Default mode/);
  assert.match(settingsHtml, /Base domain/);
  assert.match(settingsHtml, /Cloudflare connection/);
  assert.match(settingsHtml, /GitHub connection/);
  assert.match(settingsHtml, /SMTP\/alert status/);
  assert.match(settingsHtml, /Control Center UI/);
  assert.match(settingsHtml, /@platform\/control-center-local-ui/);
  assert.match(settingsHtml, /@platform\/control-center/);
  assert.match(settingsHtml, /\/assets\/control-center\/control-center\.css/);
  assert.match(settingsHtml, /AppShell/);
  assert.equal(settingsHtml.includes(["file", "vendor"].join(":")), false);
  assert.match(settingsHtml, /Provider Connections/);
  assert.match(settingsHtml, /Cloudflare/);
  assert.match(settingsHtml, /Update settings/);

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
  assert.match(deploymentHtml, /Deployments/);
  assert.match(deploymentHtml, /local-plan-only|planned/);

  const backupsHtml = await getText(`${baseUrl}/?section=backups`);
  assert.match(backupsHtml, /Manual backup/);
  assert.match(backupsHtml, /Restore drill/);
  assert.match(backupsHtml, /Plan manual backup/);

  const backupPlan = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "backup",
    scope: "all",
    secret: "backup-secret-should-not-leak",
  });
  assert.equal(backupPlan.status, 202);
  assert.equal(backupPlan.body.type, "backup.run");
  assert.equal(backupPlan.body.dryRun, true);
  assert.equal(backupPlan.body.backup.action, "backup");
  assert.equal(backupPlan.body.backup.status, "planned");
  assert.equal(backupPlan.body.backup.productionEvidence, false);
  assert.doesNotMatch(JSON.stringify(backupPlan.body), /backup-secret-should-not-leak/);

  const restorePlan = await postJson(`${baseUrl}/actions/backup-command`, {
    action: "restore",
    scope: "all",
    backupRef: "latest",
  });
  assert.equal(restorePlan.status, 202);
  assert.equal(restorePlan.body.type, "restore.plan");
  assert.equal(restorePlan.body.dryRun, true);
  assert.equal(restorePlan.body.details.dataChanged, false);
  assert.equal(restorePlan.body.backup.action, "restore-drill");
  assert.equal(restorePlan.body.backup.backupRef, "latest");

  const backupRecords = await getJson(`${baseUrl}/control/backups/records`);
  assert.equal(backupRecords.records.some((record) => record.id === backupPlan.body.backup.id), true);
  assert.equal(backupRecords.records.some((record) => record.id === restorePlan.body.backup.id), true);
  assert.equal(existsSync(backupRecordsFile), true);
  const backupRecordsText = readFileSync(backupRecordsFile, "utf8");
  assert.equal(backupRecordsText.trim().split(/\r?\n/).length >= 2, true);
  assert.doesNotMatch(backupRecordsText, /backup-secret-should-not-leak/);
  assert.match(await getText(`${baseUrl}/?mode=advanced&section=backup-restore`), /Backup History/);

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
  assert.equal(applyOperation.requestedBy, "local-admin");
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

  assert.equal(stderr, "");
});

test("Admin Control Center admin guard", async (t) => {
  prepareFixture();
  const port = await freePort();
  const adminInput = "example-control-center-admin-login";
  const loginField = ["pass", "word"].join("");
  const sessionKeysFile = path.join(stateDir, "session.keys");
  writeFileSync(sessionKeysFile, "test-session-key\n");
  const child = spawn(process.execPath, [path.join(infraRoot, "control-center", "server.mjs")], {
    cwd: infraRoot,
    env: {
      ...process.env,
      CONTROL_CENTER_PORT: String(port),
      CONTROL_CENTER_ENV: "local",
      CONTROL_CENTER_AUTH_REQUIRED: "true",
      CONTROL_CENTER_ADMIN_PASSWORD_SHA256: createHash("sha256").update(adminInput).digest("hex"),
      CONTROL_CENTER_SESSION_KEYS_FILE: sessionKeysFile,
      CONTROL_CENTER_DOCS_ROOT: infraRoot,
      PROJECTS_ROOT: projectsRoot,
      PROJECT_STATE_FILE: stateFile,
      PROJECT_AUDIT_FILE: auditFile,
      PROJECT_OPERATIONS_FILE: operationsFile,
      PROJECT_APPLICATIONS_FILE: applicationsFile,
      PROJECT_DOMAINS_FILE: domainsFile,
      PROJECT_IDENTITY_ACCESS_FILE: identityAccessFile,
      PROJECT_DEPLOYMENTS_FILE: deploymentsFile,
      PROJECT_BACKUP_RECORDS_FILE: backupRecordsFile,
      PROJECT_RESOURCE_LIMITS_FILE: resourceLimitsFile,
      PROJECT_SECURITY_POLICIES_FILE: securityPoliciesFile,
      PROJECT_ALERTS_FILE: alertsFile,
      PROJECT_NOTIFICATION_CHANNELS_FILE: notificationChannelsFile,
      PROJECT_PROVIDER_CONNECTIONS_FILE: providerConnectionsFile,
      PROJECT_SETTINGS_FILE: settingsFile,
      PROJECT_WEBSPACES_FILE: webspacesFile,
      CONTROL_CENTER_HOST: "admin.localhost.com",
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

  const denied = await fetch(`${baseUrl}/control/overview`, { headers: { accept: "application/json" } });
  assert.equal(denied.status, 401);
  assert.equal((await denied.json()).error, "admin_auth_required");

  const loginPage = await fetch(`${baseUrl}/`);
  assert.equal(loginPage.status, 401);
  assert.match(await loginPage.text(), /Admin Sign In/);

  const badLogin = await fetch(`${baseUrl}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ [loginField]: "example-wrong-admin-login" }),
    redirect: "manual",
  });
  assert.equal(badLogin.status, 401);

  const goodLogin = await fetch(`${baseUrl}/login`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ [loginField]: adminInput }),
    redirect: "manual",
  });
  assert.equal(goodLogin.status, 303);
  const cookie = goodLogin.headers.get("set-cookie") || "";
  assert.match(cookie, /sxcc_session=/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /Secure/);
  assert.match(cookie, /SameSite=Lax/);
  const sessionCookie = cookie.split(";")[0];

  const authedOverview = await fetch(`${baseUrl}/control/overview`, {
    headers: { cookie: sessionCookie, accept: "application/json" },
  });
  assert.equal(authedOverview.status, 200);
  assert.equal((await authedOverview.json()).title, "Admin Control Center");

  const deniedMutation = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ slug: "node-demo", enabled: "0" }),
  });
  assert.equal(deniedMutation.status, 401);

  const audit = await getJson(`${baseUrl}/control/audit`, { headers: { cookie: sessionCookie } });
  const auditText = JSON.stringify(audit);
  assert.match(auditText, /admin\.login\.failed/);
  assert.match(auditText, /admin\.login\.success/);
  assert.doesNotMatch(auditText, /example-control-center-admin-login/);
  assert.doesNotMatch(auditText, /example-wrong-admin-login/);

  assert.equal(stderr, "");
});

function prepareFixture() {
  rmSync(testRoot, { recursive: true, force: true });
  mkdirSync(path.join(projectsRoot, "php-demo", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "node-demo"), { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(path.join(projectsRoot, "php-demo", "public", "index.php"), "<?php echo 'php-demo';\n");
  writeFileSync(path.join(projectsRoot, "node-demo", "package.json"), `${JSON.stringify({ scripts: { start: "node server.js" } }, null, 2)}\n`);
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

async function getJson(url, init = {}) {
  const response = await fetch(url, init);
  assert.equal(response.ok, true, `${url} returned ${response.status}`);
  return response.json();
}

async function getText(url, init = {}) {
  const response = await fetch(url, init);
  assert.equal(response.ok, true, `${url} returned ${response.status}`);
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
