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
const deploymentsFile = path.join(stateDir, "deployments.jsonl");
const backupRecordsFile = path.join(stateDir, "backups.jsonl");
const resourceLimitsFile = path.join(stateDir, "resource-limits.json");
const webspacesFile = path.join(stateDir, "webspaces.json");

test("Stexor Control Center local foundation", async (t) => {
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
      PROJECT_DEPLOYMENTS_FILE: deploymentsFile,
      PROJECT_BACKUP_RECORDS_FILE: backupRecordsFile,
      PROJECT_RESOURCE_LIMITS_FILE: resourceLimitsFile,
      PROJECT_WEBSPACES_FILE: webspacesFile,
      PROJECTS_HOST: "projects.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
      NODE_PROJECT_HOSTS: "stexor=stexor.localhost.com",
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
  assert.match(html, /Stexor Control Center/);
  assert.match(html, /Simple/);
  assert.match(html, /Advanced/);
  assert.match(html, /Anniversary/);
  assert.match(html, /Stexor/);

  const advancedHtml = await getText(`${baseUrl}/?mode=advanced&section=infrastructure`);
  assert.match(advancedHtml, /Infrastructure/);
  assert.match(advancedHtml, /Traefik/);
  assert.match(advancedHtml, /cAdvisor/);

  const applicationsHtml = await getText(`${baseUrl}/?section=applications`);
  assert.match(applicationsHtml, /Applications/);
  assert.match(applicationsHtml, /Deploy/);
  assert.match(applicationsHtml, /Rollback/);

  const overview = await getJson(`${baseUrl}/control/overview`);
  assert.equal(overview.title, "Stexor Control Center");
  assert.equal(overview.environment, "local");
  assert.equal(overview.modeEvidence, "local evidence only");
  assert.equal(overview.projects.total, 2);
  assert.equal(overview.projects.active, 2);
  assert.equal(overview.subdomains.total, 2);
  assert.equal(overview.subdomains.active, 2);
  assert.notEqual(overview.modeEvidence, "production evidence");

  const projects = await getJson(`${baseUrl}/control/projects`);
  assert.deepEqual(projects.projects.map((project) => [project.slug, project.type]), [
    ["anniversary", "PHP"],
    ["stexor", "Node"],
  ]);

  const projectsHtml = await getText(`${baseUrl}/?section=projects`);
  assert.match(projectsHtml, /ARCHIVE-PROJECT/);
  assert.match(projectsHtml, /DELETE-PROJECT:anniversary/);

  const updatePlan = await postJson(`${baseUrl}/control/projects/stexor/update`, {
    displayName: "Stexor Local",
  });
  assert.equal(updatePlan.status, 202);
  assert.equal(updatePlan.body.type, "project.update");
  assert.equal(updatePlan.body.dryRun, true);

  const updateApply = await postJson(`${baseUrl}/control/projects/stexor/update`, {
    displayName: "Stexor Local",
    confirm: "UPDATE-PROJECT",
  });
  assert.equal(updateApply.status, 202);
  assert.equal(updateApply.body.type, "project.update.local");
  assert.equal(updateApply.body.dryRun, false);

  const archivePlan = await postJson(`${baseUrl}/control/projects/anniversary/archive/plan`, {});
  assert.equal(archivePlan.status, 202);
  assert.equal(archivePlan.body.type, "project.archive");
  assert.equal(archivePlan.body.details.confirmationRequired, "ARCHIVE-PROJECT");

  const archiveRejected = await postJson(`${baseUrl}/control/projects/anniversary/archive/apply`, {
    confirm: "wrong",
  });
  assert.equal(archiveRejected.status, 409);

  const archiveApply = await postJson(`${baseUrl}/control/projects/anniversary/archive/apply`, {
    confirm: "ARCHIVE-PROJECT",
  });
  assert.equal(archiveApply.status, 202);
  assert.equal(archiveApply.body.type, "project.archive.local");
  assert.equal(archiveApply.body.details.filesystemTouched, false);

  const projectsAfterArchive = await getJson(`${baseUrl}/control/projects`);
  const archivedProject = projectsAfterArchive.projects.find((project) => project.slug === "anniversary");
  assert.equal(archivedProject.status, "archived");
  assert.equal(archivedProject.enabled, false);
  const overviewAfterArchive = await getJson(`${baseUrl}/control/overview`);
  assert.equal(overviewAfterArchive.projects.archived, 1);

  const deletePlan = await postJson(`${baseUrl}/control/projects/anniversary/delete/plan`, {});
  assert.equal(deletePlan.status, 202);
  assert.equal(deletePlan.body.type, "project.delete");
  assert.equal(deletePlan.body.details.confirmationRequired, "DELETE-PROJECT:anniversary");

  const deleteRejected = await postJson(`${baseUrl}/control/projects/anniversary/delete/apply`, {
    confirm: "DELETE-PROJECT",
  });
  assert.equal(deleteRejected.status, 409);

  const deleteApply = await postJson(`${baseUrl}/control/projects/anniversary/delete/apply`, {
    confirm: "DELETE-PROJECT:anniversary",
  });
  assert.equal(deleteApply.status, 202);
  assert.equal(deleteApply.body.type, "project.delete.local");
  assert.equal(deleteApply.body.details.filesystemTouched, false);
  assert.equal(deleteApply.body.details.databaseTouched, false);
  assert.equal(existsSync(path.join(projectsRoot, "anniversary", "public", "index.php")), true);

  const projectsAfterDelete = await getJson(`${baseUrl}/control/projects`);
  assert.equal(projectsAfterDelete.projects.some((project) => project.slug === "anniversary"), false);
  assert.equal(projectsAfterDelete.projects.some((project) => project.slug === "stexor"), true);

  const prodLocalhostPlan = await postJson(`${baseUrl}/control/subdomains/plan`, {
    environment: "production",
    projectId: "stexor",
    hostname: "bad.localhost.com",
  });
  assert.equal(prodLocalhostPlan.status, 422);
  assert.match(prodLocalhostPlan.body.message, /real domain/);

  const prodApplyWithoutConfirm = await postJson(`${baseUrl}/control/subdomains/apply`, {
    environment: "production",
    projectId: "stexor",
    hostname: "app.example.com",
  });
  assert.equal(prodApplyWithoutConfirm.status, 409);
  assert.match(prodApplyWithoutConfirm.body.message, /APPLY-PRODUCTION/);

  const prodApplyDisabled = await postJson(`${baseUrl}/control/subdomains/apply`, {
    environment: "production",
    projectId: "stexor",
    hostname: "app.example.com",
    confirm: "APPLY-PRODUCTION",
  });
  assert.equal(prodApplyDisabled.status, 409);
  assert.match(prodApplyDisabled.body.message, /disabled/);

  const domainsHtml = await getText(`${baseUrl}/?section=domains`);
  assert.match(domainsHtml, /Add local/);
  assert.match(domainsHtml, /Discovered route/);

  const uiSubdomainApply = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "apply-local",
    projectId: "stexor",
    hostname: "stexor-ui.localhost.com",
    visibility: "admin",
    protection: "passkey",
    secret: "subdomain-ui-secret-should-not-leak",
  });
  assert.equal(uiSubdomainApply.status, 202);
  assert.equal(uiSubdomainApply.body.type, "subdomain.apply.local");
  assert.equal(uiSubdomainApply.body.details.hostname, "stexor-ui.localhost.com");
  assert.equal(uiSubdomainApply.body.details.visibility, "admin");
  assert.equal(uiSubdomainApply.body.details.protection, "passkey");
  assert.doesNotMatch(JSON.stringify(uiSubdomainApply.body), /subdomain-ui-secret-should-not-leak/);

  const uiSubdomainVerify = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "verify",
    id: "stexor-ui-localhost-com",
  });
  assert.equal(uiSubdomainVerify.status, 202);
  assert.equal(uiSubdomainVerify.body.type, "subdomain.verify");

  const uiRemoveRejected = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "remove",
    id: "stexor-ui-localhost-com",
    confirm: "wrong",
  });
  assert.equal(uiRemoveRejected.status, 409);

  const uiRemoveApply = await postJson(`${baseUrl}/actions/subdomain-command`, {
    action: "remove",
    id: "stexor-ui-localhost-com",
    confirm: "REMOVE-SUBDOMAIN",
  });
  assert.equal(uiRemoveApply.status, 202);
  assert.equal(uiRemoveApply.body.type, "subdomain.remove");

  const domainsAfterUiRemove = await getJson(`${baseUrl}/control/domains`);
  assert.equal(domainsAfterUiRemove.subdomains.some((item) => item.hostname === "stexor-ui.localhost.com"), false);

  const invalidWebspace = await postJson(`${baseUrl}/control/webspaces`, {
    projectId: "stexor",
    basePath: "../secret",
  });
  assert.equal(invalidWebspace.status, 422);
  assert.match(invalidWebspace.body.message, /Invalid webspace path/);

  const webspacesHtml = await getText(`${baseUrl}/?section=webspaces`);
  assert.match(webspacesHtml, /Create space/);
  assert.match(webspacesHtml, /public, private, uploads, backups, config/);

  const webspacePlan = await postJson(`${baseUrl}/control/webspaces`, {
    projectId: "stexor",
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
    projectId: "stexor",
    name: "media",
    quotaBytes: 4096,
    confirm: "CREATE-WEBSPACE",
    secret: "webspace-secret-should-not-leak",
  });
  assert.equal(webspaceApply.status, 202);
  assert.equal(webspaceApply.body.type, "webspace.create.local");
  assert.equal(webspaceApply.body.dryRun, false);
  assert.equal(webspaceApply.body.webspace.id, "stexor-media");
  assert.deepEqual(webspaceApply.body.webspace.mounts, ["public", "private", "uploads", "backups", "config"]);
  assert.equal(webspaceApply.body.details.filesystemTouched, false);

  const quotaPlan = await postJson(`${baseUrl}/control/webspaces/stexor-media/quota`, {
    quotaBytes: 8192,
  });
  assert.equal(quotaPlan.status, 202);
  assert.equal(quotaPlan.body.type, "webspace.quota");
  assert.equal(quotaPlan.body.details.confirmationRequired, "UPDATE-QUOTA");

  const quotaApply = await postJson(`${baseUrl}/control/webspaces/stexor-media/quota`, {
    quotaBytes: 8192,
    confirm: "UPDATE-QUOTA",
  });
  assert.equal(quotaApply.status, 202);
  assert.equal(quotaApply.body.type, "webspace.quota.local");
  assert.equal(quotaApply.body.webspace.quotaBytes, 8192);

  const webspacesAfterApply = await getJson(`${baseUrl}/control/webspaces`);
  const mediaSpace = webspacesAfterApply.webspaces.find((space) => space.id === "stexor-media");
  assert.equal(mediaSpace.quotaBytes, 8192);
  assert.equal(mediaSpace.basePath, "webspaces/stexor/media");
  assert.equal(existsSync(webspacesFile), true);
  const webspaceStateText = readFileSync(webspacesFile, "utf8");
  assert.doesNotMatch(webspaceStateText, /webspace-secret-should-not-leak/);
  assert.equal(JSON.parse(webspaceStateText)["stexor-media"].quotaBytes, 8192);

  const resourcesHtml = await getText(`${baseUrl}/?section=resources`);
  assert.match(resourcesHtml, /Resources/);
  assert.match(resourcesHtml, /Quota per project/);
  assert.match(resourcesHtml, /Set limits/);

  const invalidResourceLimit = await postJson(`${baseUrl}/control/resources/limits`, {
    projectId: "stexor",
    memoryMb: -1,
  });
  assert.equal(invalidResourceLimit.status, 422);
  assert.match(invalidResourceLimit.body.message, /Memory MB/);

  const resourceLimitPlan = await postJson(`${baseUrl}/control/resources/limits`, {
    projectId: "stexor",
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
    projectId: "stexor",
    cpuMillicores: 750,
    memoryMb: 512,
    diskMb: 2048,
    confirm: "UPDATE-RESOURCE-LIMITS",
    secret: "resource-limit-secret-should-not-leak",
  });
  assert.equal(resourceLimitApply.status, 202);
  assert.equal(resourceLimitApply.body.type, "resources.limits.local");
  assert.equal(resourceLimitApply.body.dryRun, false);
  assert.equal(resourceLimitApply.body.resourceLimit.projectId, "stexor");
  assert.equal(resourceLimitApply.body.resourceLimit.cpuMillicores, 750);
  assert.equal(resourceLimitApply.body.resourceLimit.memoryMb, 512);
  assert.equal(resourceLimitApply.body.resourceLimit.diskMb, 2048);
  assert.equal(resourceLimitApply.body.resourceLimit.dockerTouched, false);
  assert.doesNotMatch(JSON.stringify(resourceLimitApply.body), /resource-limit-secret-should-not-leak/);

  const resourceSummary = await getJson(`${baseUrl}/control/resources/summary`);
  const stexorLimit = resourceSummary.projectLimits.find((limit) => limit.projectId === "stexor");
  assert.equal(stexorLimit.cpuMillicores, 750);
  assert.equal(stexorLimit.memoryMb, 512);
  assert.equal(stexorLimit.diskMb, 2048);
  assert.equal(existsSync(resourceLimitsFile), true);
  const resourceLimitText = readFileSync(resourceLimitsFile, "utf8");
  assert.doesNotMatch(resourceLimitText, /resource-limit-secret-should-not-leak/);
  assert.equal(JSON.parse(resourceLimitText).stexor.diskMb, 2048);

  const deployPlan = await postJson(`${baseUrl}/control/applications/stexor/deploy`, {
    branch: "main",
    commit: "abc1234",
    cloudflareToken: "super-secret-token-should-not-leak",
  });
  assert.equal(deployPlan.status, 202);
  assert.equal(deployPlan.body.type, "application.deploy");
  assert.equal(deployPlan.body.dryRun, true);
  assert.equal(deployPlan.body.projectId, "stexor");
  assert.equal(deployPlan.body.deployment.action, "deploy");
  assert.equal(deployPlan.body.deployment.status, "planned");
  assert.equal(deployPlan.body.deployment.releaseEvidence, "local-plan-only");
  assert.equal(deployPlan.body.deployment.productionApproval, "required-for-production");
  assert.doesNotMatch(JSON.stringify(deployPlan.body), /super-secret-token-should-not-leak/);
  assert.doesNotMatch(JSON.stringify(deployPlan.body), /cloudflareToken/);

  const rollbackPlan = await postJson(`${baseUrl}/control/applications/stexor/rollback`, {
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
    projectId: "stexor",
    hostname: "stexor-preview.localhost.com",
    confirm: "APPLY-LOCAL",
    cloudflareToken: "super-secret-token-should-not-leak",
  });
  assert.equal(localApply.status, 202);
  assert.equal(localApply.body.type, "subdomain.apply.local");
  assert.equal(localApply.body.id, localApply.body.operationId);
  assert.equal(localApply.body.projectId, "stexor");
  assert.equal(localApply.body.environment, "local");
  assert.equal(localApply.body.dryRun, false);
  assert.equal(localApply.body.details.productionEvidence, false);
  assert.equal(localApply.body.steps.every((step) => step.operationId === localApply.body.id), true);
  assert.equal(localApply.body.steps.every((step) => step.output === "sanitized"), true);
  assert.doesNotMatch(JSON.stringify(localApply.body), /super-secret-token-should-not-leak/);
  assert.doesNotMatch(JSON.stringify(localApply.body), /cloudflareToken/);

  const domainsWithPreview = await getJson(`${baseUrl}/control/domains`);
  assert.equal(domainsWithPreview.subdomains.some((item) => item.hostname === "stexor-preview.localhost.com"), true);

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

  const removePreview = await postJson(`${baseUrl}/control/subdomains/stexor-preview-localhost-com/remove/apply`, {
    confirm: "REMOVE-SUBDOMAIN",
  });
  assert.equal(removePreview.status, 202);

  const domainsAfterRemove = await getJson(`${baseUrl}/control/domains`);
  assert.equal(domainsAfterRemove.subdomains.some((item) => item.hostname === "stexor-preview.localhost.com"), false);

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

test("Stexor Control Center admin guard", async (t) => {
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
      PROJECT_DEPLOYMENTS_FILE: deploymentsFile,
      PROJECT_BACKUP_RECORDS_FILE: backupRecordsFile,
      PROJECT_RESOURCE_LIMITS_FILE: resourceLimitsFile,
      PROJECT_WEBSPACES_FILE: webspacesFile,
      PROJECTS_HOST: "projects.localhost.com",
      PROJECT_HOST_SUFFIX: ".localhost.com",
      NODE_PROJECT_HOSTS: "stexor=stexor.localhost.com",
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
  assert.equal((await authedOverview.json()).title, "Stexor Control Center");

  const deniedMutation = await fetch(`${baseUrl}/actions/toggle-project`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ slug: "stexor", enabled: "0" }),
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
  mkdirSync(path.join(projectsRoot, "anniversary", "public"), { recursive: true });
  mkdirSync(path.join(projectsRoot, "stexor"), { recursive: true });
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(path.join(projectsRoot, "anniversary", "public", "index.php"), "<?php echo 'anniversary';\n");
  writeFileSync(path.join(projectsRoot, "stexor", "package.json"), `${JSON.stringify({ scripts: { start: "node server.js" } }, null, 2)}\n`);
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

async function getText(url) {
  const response = await fetch(url);
  assert.equal(response.ok, true, `${url} returned ${response.status}`);
  return response.text();
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
