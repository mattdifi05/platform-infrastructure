import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";

const SOURCE_FINGERPRINTS = new Map([
  ["control-center/auth/oidc.mjs", "2f0c9ea5239935857caab3f233ff43cdb81a34d8ab77cfc1a7a00c2a1b7b91b1"],
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["control-center/backup/contracts.mjs", "a425629471d4f98af4c0f09ca700d41260207d447adec2f9eb6476148b35450e"],
  ["control-center/AUTHENTICATION.md", "1e22e3474fe4cde9711c0e4d2a0aabdb3bf74e12dc1415cb4f9915f28f3b9bda"],
  ["control-center/CONTROL-CENTER-CORE.md", "ebe63523cf848c49e8f87e75e80a671bb4b03040e39ea09f3f6b026c80d12404"],
  ["scripts/backup-scheduler.sh", "2f8e0d62c5bcd04367a4ba7d6f259945e6a3a8698db8938de99fec74924b942b"],
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["compose.backup-scheduler.yaml", "cf2ad09cd02f3a04c512450f0c730ec6637ac86646d9037c0be118a12c95c748"],
  ["compose.runtime-isolation.yaml", "69d7383d8f0d499d0580514e30944a6819e14631619f536587420696d2238fc6"],
]);

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireRealDirectory(target, label) {
  const stat = lstatSync(target);
  assert(stat.isDirectory() && !stat.isSymbolicLink(), `${label} must be a real directory`);
  assert(realpathSync(target) === target, `${label} must be supplied by physical path`);
  return stat;
}

function sliceBetween(source, start, end, label) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert(startIndex >= 0 && endIndex > startIndex, `cannot isolate ${label}`);
  return source.slice(startIndex, endIndex);
}

function requireText(source, fragment, label) {
  assert(source.includes(fragment), `missing ${label}`);
}

function forbidText(source, expression, label) {
  assert(!expression.test(source), `unexpected ${label}`);
}

function validateOwnership(sourceArgument, labArgument) {
  const rootValue = process.env.FG069_WRAPPER_TEMP_ROOT || "";
  const sentinelValue = process.env.FG069_OWNERSHIP_SENTINEL || "";
  const token = process.env.FG069_OWNERSHIP_TOKEN || "";
  assert(rootValue && sentinelValue && token, "missing FG069 wrapper ownership environment");
  assert(/^[0-9a-f]{64}$/.test(token), "ownership token must be 256-bit lowercase hex");

  const root = path.resolve(rootValue);
  const sentinel = path.resolve(sentinelValue);
  const expectedSentinel = path.join(root, `.fg069-owner-${token}`);
  assert(sentinel === expectedSentinel, "ownership token does not match sentinel name");

  requireRealDirectory(root, "wrapper root");
  const sourceRoot = path.resolve(sourceArgument || "");
  const labRoot = path.resolve(labArgument || "");
  assert(sourceRoot === path.join(root, "source"), "source root is not the wrapper-owned exact child");
  assert(labRoot === path.join(root, "lab"), "lab root is not the wrapper-owned exact child");
  requireRealDirectory(sourceRoot, "archived source root");
  requireRealDirectory(labRoot, "laboratory root");

  const sentinelStat = lstatSync(sentinel);
  assert(sentinelStat.isFile() && !sentinelStat.isSymbolicLink(), "ownership sentinel must be a regular file");
  assert(realpathSync(sentinel) === sentinel, "ownership sentinel must be supplied by physical path");
  assert(readFileSync(sentinel, "utf8") === `FG069-OWNER:${token}\n`, "ownership sentinel content mismatch");
  assert(!existsSync(path.join(sourceRoot, ".git")), "source must be an archive without Git metadata");
  assert(readdirSync(labRoot).length === 0, "laboratory must be empty before the probe");
  return { sourceRoot, labRoot };
}

function readPinnedSources(sourceRoot) {
  const sources = new Map();
  for (const [relative, expected] of SOURCE_FINGERPRINTS) {
    const target = path.join(sourceRoot, ...relative.split("/"));
    const stat = lstatSync(target);
    assert(stat.isFile() && !stat.isSymbolicLink(), `${relative} must be a regular archived file`);
    const bytes = readFileSync(target);
    assert(sha256(bytes) === expected, `${relative} fingerprint mismatch`);
    sources.set(relative, bytes.toString("utf8"));
  }
  return sources;
}

const preFixSensitivePaths = new Set([
  "/actions/vault-command",
  "/actions/database-command",
  "/actions/database-admin-login",
  "/actions/phpmyadmin-login",
  "/actions/phppgadmin-login",
  "/actions/backup-command",
  "/actions/identity-command",
  "/actions/settings-command",
]);

function preFixAuthorize({ role, pathname, fresh = true, method = "POST" }) {
  const sensitive = preFixSensitivePaths.has(pathname);
  if (sensitive && role !== "owner") return 403;
  if (sensitive && !fresh) return 428;
  const mutating = !["GET", "HEAD", "OPTIONS"].includes(method);
  if (mutating && !["owner", "admin"].includes(role)) return 403;
  return 200;
}

function normalizeControlAlias(pathname) {
  return pathname.replace(/^\/control\/v1(?=\/)/, "/control");
}

function backupSemantic(pathname, requestedScope = "platform:all") {
  const normalized = normalizeControlAlias(pathname);
  if (normalized === "/control/backups/run" || normalized === "/actions/backup-command") {
    return { operation: "backup", scope: requestedScope };
  }
  const database = normalized.match(/^\/control\/databases\/([a-z0-9-]+)\/backup$/);
  if (database) return { operation: "backup", scope: `database:${database[1]}` };
  return null;
}

function fixedAuthorize({ role, pathname, fresh = true, method = "POST", scope = "platform:all" }) {
  const backup = backupSemantic(pathname, scope);
  if (backup) {
    if (role !== "owner") return 403;
    if (!fresh) return 428;
  }
  const mutating = !["GET", "HEAD", "OPTIONS"].includes(method);
  if (mutating && !["owner", "admin"].includes(role)) return 403;
  return 200;
}

class VulnerableSyntheticQueue {
  constructor() {
    this.sequence = 0;
    this.jobs = [];
  }

  submit({ principal, scope }) {
    this.sequence += 1;
    const job = Object.freeze({
      id: `synthetic-pre-fix-${String(this.sequence).padStart(4, "0")}`,
      operation: "backup",
      principal,
      scope,
      status: "queued",
    });
    this.jobs.push(job);
    return job;
  }
}

class FixedSyntheticQueue {
  constructor({
    maxDepth = 3,
    maxPerPrincipal = 2,
    principalWindowMs = 60_000,
    maxConcurrency = 1,
    retention = 4,
    now = () => Date.now(),
  } = {}) {
    this.maxDepth = maxDepth;
    this.maxPerPrincipal = maxPerPrincipal;
    this.principalWindowMs = principalWindowMs;
    this.maxConcurrency = maxConcurrency;
    this.retention = retention;
    this.now = now;
    this.sequence = 0;
    this.queued = [];
    this.running = [];
    this.terminal = [];
    this.active = new Map();
    this.principalAdmissions = new Map();
  }

  outstandingDepth() {
    return this.queued.length + this.running.length;
  }

  submit({ principal, pathname, scope }) {
    const semantic = backupSemantic(pathname, scope);
    if (!semantic) return { accepted: false, reason: "unsupported_operation" };
    const activeKey = `${semantic.operation}:${semantic.scope}`;
    if (this.active.has(activeKey)) {
      return { accepted: false, reason: "duplicate_active", existingId: this.active.get(activeKey).id };
    }
    if (this.outstandingDepth() >= this.maxDepth) return { accepted: false, reason: "queue_full" };
    const now = this.now();
    const admitted = (this.principalAdmissions.get(principal) || [])
      .filter((timestamp) => now - timestamp < this.principalWindowMs);
    if (admitted.length >= this.maxPerPrincipal) {
      this.principalAdmissions.set(principal, admitted);
      return { accepted: false, reason: "principal_rate" };
    }

    this.sequence += 1;
    const job = {
      id: `synthetic-fixed-${String(this.sequence).padStart(4, "0")}`,
      operation: semantic.operation,
      scope: semantic.scope,
      principal,
      activeKey,
      status: "queued",
    };
    this.queued.push(job);
    this.active.set(activeKey, job);
    admitted.push(now);
    this.principalAdmissions.set(principal, admitted);
    return { accepted: true, job };
  }

  submitReferenceBatch(requests) {
    return requests.map((request) => this.submit(request));
  }

  startNext() {
    if (this.running.length >= this.maxConcurrency) return { started: false, reason: "concurrency_full" };
    const job = this.queued.shift();
    if (!job) return { started: false, reason: "queue_empty" };
    job.status = "running";
    this.running.push(job);
    return { started: true, job };
  }

  finish(jobId, status = "done") {
    const index = this.running.findIndex((job) => job.id === jobId);
    assert(index >= 0, "synthetic fixed control cannot finish a non-running job");
    const [job] = this.running.splice(index, 1);
    job.status = status;
    this.active.delete(job.activeKey);
    this.terminal.push(job);
    if (this.terminal.length > this.retention) {
      this.terminal.splice(0, this.terminal.length - this.retention);
    }
    return job;
  }
}

function inspectSource(sources) {
  const oidc = sources.get("control-center/auth/oidc.mjs");
  const server = sources.get("control-center/server.mjs");
  const contracts = sources.get("control-center/backup/contracts.mjs");
  const authentication = sources.get("control-center/AUTHENTICATION.md");
  const apiContract = sources.get("control-center/CONTROL-CENTER-CORE.md");
  const scheduler = sources.get("scripts/backup-scheduler.sh");
  const infraOps = sources.get("scripts/infra-ops.mjs");
  const schedulerCompose = sources.get("compose.backup-scheduler.yaml");
  const runtimeIsolation = sources.get("compose.runtime-isolation.yaml");

  const sensitiveFunction = sliceBetween(oidc, "function isSensitivePath(pathname)", "function normalizeSessionRow", "sensitive-path function");
  requireText(sensitiveFunction, '"/actions/backup-command"', "legacy backup sensitivity");
  assert(!sensitiveFunction.includes("/control/backups/run"), "modern backup route unexpectedly classified sensitive");
  assert(!sensitiveFunction.includes("/control/v1/backups/run"), "versioned backup route unexpectedly classified sensitive");
  requireText(oidc, 'if (mutating && !["owner", "admin"].includes(session.role))', "admin mutation authorization");
  requireText(oidc, 'String(req.headers.origin || "") !== this.config.publicOrigin', "exact-origin CSRF control");
  requireText(oidc, 'String(req.headers["sec-fetch-site"] || "").toLowerCase() !== "same-origin"', "Fetch Metadata CSRF control");
  requireText(oidc, 'req.headers["x-csrf-token"] || payload._csrf', "session-bound CSRF token control");

  requireText(server, 'if (parts[0] === "control" && parts[1] === "v1") return ["control", ...parts.slice(2)];', "version alias normalization");
  requireText(server, 'route(parts, "control", "backups", "run")', "platform backup route");
  requireText(server, 'route([parts[0], parts[1], parts[3]], "control", "databases", "backup")', "database backup route");
  assert(server.indexOf("controlAuth.authorize(req, url, session)") < server.indexOf("await handleApi(req, res, url, context)"), "raw path authorization must occur before route normalization");

  const queueBackup = sliceBetween(server, "function queueBackupRun(payload, context)", "function queueRestoreDrill", "backup queue function");
  requireText(queueBackup, 'createBackupJob({ operation: "backup", scope, resources, context })', "backup job creation");
  requireText(queueBackup, 'result: "accepted"', "unconditional queue acceptance audit");
  const createJob = sliceBetween(server, "function createBackupJob({", "function readBackupJobs", "backup job persistence function");
  requireText(createJob, "id: rid()", "fresh job identifier");
  requireText(createJob, 'path.join(backupJobsDir, "queued")', "durable queued directory");
  requireText(createJob, 'writePrivateJsonAtomic(path.join(queuedDir, `${job.id}.json`), job);', "unique durable job write");
  forbidText(createJob, /dedup|idempoten|maxQueue|queueDepth|rateLimit|concurr/i, "queue admission bound");
  const inventory = sliceBetween(server, "function readBackupJobs()", "function renderControlCenter", "backup inventory function");
  requireText(inventory, ".slice(0, 200)", "per-status display slice");
  requireText(inventory, ".slice(0, 80)", "final display slice");

  requireText(contracts, "resources.length > 256", "typed resource-count bound");
  requireText(contracts, 'status: "queued"', "typed queued status");
  requireText(contracts, "Duplicate backup resource ID", "resource deduplication within one job");

  const schedulerQueue = sliceBetween(scheduler, "process_backup_job_queue()", 'if [ "${1:-}" = "--run" ]', "scheduler queue loop");
  requireText(schedulerQueue, 'find "$JOBS_DIR/queued" -maxdepth 1 -type f -name \'*.json\' 2>/dev/null | sort | head -n 1', "serial queue selection");
  requireText(schedulerQueue, 'process_backup_job "$queued_file"', "serial job processing");
  forbidText(schedulerQueue, /max[_-]?queue|queue[_-]?depth|dedup|rate[_-]?limit|concurr/i, "scheduler queue backpressure");
  requireText(scheduler, 'mv "$queued_file" "$running_file"', "atomic single-consumer claim");
  requireText(scheduler, "--run execute-backup-job --jobFile", "typed privileged execution");
  requireText(scheduler, "process_backup_job_queue &", "background queue consumer");
  requireText(infraOps, "async function executeTypedBackupResource(resource)", "typed backup resource executor");
  requireText(infraOps, "await backupPostgres({", "PostgreSQL backup execution");
  requireText(infraOps, "await backupMariadb({", "MariaDB backup execution");
  requireText(infraOps, "await backupMinio()", "MinIO backup execution");
  requireText(infraOps, "for (const resource of job.resources) artifacts.push(await executeTypedBackupResource(resource));", "serial typed resource execution");

  requireText(schedulerCompose, "BACKUP_SCHEDULER_JOBS_DIR: /var/www/project-state/backup-jobs", "shared backup jobs path");
  requireText(schedulerCompose, "./projects-portal/state:/var/www/project-state", "shared state mount");
  requireText(runtimeIsolation, "cpus: 1.00", "scheduler CPU cap");
  requireText(runtimeIsolation, "mem_limit: 512m", "scheduler memory cap");
  for (const network of ["platform_db_admin", "platform_storage", "platform_egress", "platform_docker_control"]) {
    requireText(runtimeIsolation, `- ${network}`, `${network} scheduler network`);
  }

  requireText(authentication, "Sensitive operations include Vault access, database administration, backup or", "documented backup sensitivity");
  requireText(authentication, "require an OIDC `auth_time` no older than five minutes", "documented fresh authentication");
  requireText(apiContract, "`/control/v1/*` is the versioned API surface", "versioned API contract");
  requireText(apiContract, "Existing `/control/*` routes are", "compatibility alias contract");
}

function runAuthorizationMatrix() {
  const modern = ["/control/backups/run", "/control/v1/backups/run"];
  for (const pathname of modern) {
    assert(preFixAuthorize({ role: "admin", pathname }) === 200, `${pathname} should admit admin before the fix`);
    assert(preFixAuthorize({ role: "viewer", pathname }) === 403, `${pathname} should deny viewer`);
  }
  for (const pathname of ["/control/databases/db-fixture/backup", "/control/v1/databases/db-fixture/backup"]) {
    assert(preFixAuthorize({ role: "admin", pathname }) === 200, `${pathname} should admit admin before the fix`);
  }
  assert(preFixAuthorize({ role: "admin", pathname: "/actions/backup-command" }) === 403, "legacy backup route should deny admin");
  assert(preFixAuthorize({ role: "owner", pathname: "/actions/backup-command", fresh: false }) === 428, "legacy backup route should require fresh owner authentication");
  assert(preFixAuthorize({ role: "owner", pathname: "/actions/backup-command", fresh: true }) === 200, "legacy backup route should accept fresh owner");

  for (const pathname of [
    "/control/backups/run",
    "/control/v1/backups/run",
    "/control/databases/db-fixture/backup",
    "/control/v1/databases/db-fixture/backup",
  ]) {
    assert(fixedAuthorize({ role: "admin", pathname }) === 403, `${pathname} fixed control must deny admin`);
    assert(fixedAuthorize({ role: "owner", pathname, fresh: false }) === 428, `${pathname} fixed control must require freshness`);
    assert(fixedAuthorize({ role: "owner", pathname, fresh: true }) === 200, `${pathname} fixed control must accept fresh owner`);
  }
  return modern.length;
}

function runQueueModels() {
  const vulnerable = new VulnerableSyntheticQueue();
  for (let index = 0; index < 8; index += 1) {
    vulnerable.submit({ principal: "admin-fixture", scope: "platform:all" });
  }
  assert(vulnerable.jobs.length === 8, "pre-fix model must accept every duplicate");
  assert(new Set(vulnerable.jobs.map((job) => job.id)).size === 8, "pre-fix model must assign a unique ID to every duplicate");
  const serialOrder = vulnerable.jobs.map((job) => job.id);
  assert(serialOrder.length === 8 && serialOrder[0].endsWith("0001") && serialOrder[7].endsWith("0008"), "serial scheduler model must retain all duplicate work");

  const duplicateQueue = new FixedSyntheticQueue({ maxDepth: 4, maxPerPrincipal: 4 });
  const duplicateBatch = duplicateQueue.submitReferenceBatch([
    { principal: "owner-a", pathname: "/control/backups/run", scope: "platform:all" },
    { principal: "owner-a", pathname: "/control/v1/backups/run", scope: "platform:all" },
  ]);
  assert(duplicateBatch.filter((result) => result.accepted).length === 1, "sequential duplicate control must admit one alias only");
  assert(duplicateBatch[1].reason === "duplicate_active", "version alias must share the active-operation key");

  const crossPrincipalQueue = new FixedSyntheticQueue({ maxDepth: 4, maxPerPrincipal: 4 });
  assert(crossPrincipalQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:alpha" }).accepted, "first cross-principal fixture must be accepted");
  const crossPrincipal = crossPrincipalQueue.submit({ principal: "owner-b", pathname: "/control/v1/backups/run", scope: "application:alpha" });
  assert(!crossPrincipal.accepted && crossPrincipal.reason === "duplicate_active", "cross-principal duplicate must be rejected globally");

  const fullQueue = new FixedSyntheticQueue({ maxDepth: 3, maxPerPrincipal: 2 });
  assert(fullQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:alpha" }).accepted, "full-queue fixture one must be accepted");
  assert(fullQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:beta" }).accepted, "full-queue fixture two must be accepted");
  assert(fullQueue.submit({ principal: "owner-b", pathname: "/control/backups/run", scope: "application:gamma" }).accepted, "full-queue fixture three must be accepted");
  const fullRejection = fullQueue.submit({ principal: "owner-c", pathname: "/control/backups/run", scope: "application:delta" });
  assert(!fullRejection.accepted && fullRejection.reason === "queue_full", "full queue must reject additional work");

  const completionQueue = new FixedSyntheticQueue({ maxDepth: 2, maxPerPrincipal: 2 });
  const original = completionQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "platform:all" });
  const startedOriginal = completionQueue.startNext();
  assert(original.accepted && startedOriginal.started, "completion fixture must start");
  completionQueue.finish(startedOriginal.job.id);
  const retry = completionQueue.submit({ principal: "owner-a", pathname: "/control/v1/backups/run", scope: "platform:all" });
  assert(retry.accepted && retry.job.id !== original.job.id, "completion then deliberate retry must be accepted");

  let rateNow = 1_000;
  const rateQueue = new FixedSyntheticQueue({
    maxDepth: 5,
    maxPerPrincipal: 2,
    principalWindowMs: 60_000,
    now: () => rateNow,
  });
  assert(rateQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:a" }).accepted, "rate fixture one must be accepted");
  assert(rateQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:b" }).accepted, "rate fixture two must be accepted");
  const rateRejection = rateQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:c" });
  assert(!rateRejection.accepted && rateRejection.reason === "principal_rate", "per-principal rate must reject excess work");
  rateNow += 60_000;
  const rateAfterExpiry = rateQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:d" });
  assert(rateAfterExpiry.accepted, "per-principal rate window must release capacity after expiry");

  const concurrencyQueue = new FixedSyntheticQueue({ maxDepth: 3, maxPerPrincipal: 3, maxConcurrency: 1 });
  assert(concurrencyQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:a" }).accepted, "concurrency fixture one must be accepted");
  assert(concurrencyQueue.submit({ principal: "owner-a", pathname: "/control/backups/run", scope: "application:b" }).accepted, "concurrency fixture two must be accepted");
  const firstStart = concurrencyQueue.startNext();
  const blockedStart = concurrencyQueue.startNext();
  assert(firstStart.started && !blockedStart.started && blockedStart.reason === "concurrency_full", "concurrency one must be enforced");
  concurrencyQueue.finish(firstStart.job.id);
  assert(concurrencyQueue.startNext().started, "next job may start after capacity is released");

  const retentionQueue = new FixedSyntheticQueue({ maxDepth: 2, maxPerPrincipal: 2, retention: 4 });
  for (let index = 0; index < 5; index += 1) {
    const accepted = retentionQueue.submit({
      principal: `owner-${index}`,
      pathname: "/control/backups/run",
      scope: `application:retention-${index}`,
    });
    assert(accepted.accepted, "retention fixture admission failed");
    const started = retentionQueue.startNext();
    assert(started.started, "retention fixture start failed");
    retentionQueue.finish(started.job.id);
  }
  assert(retentionQueue.terminal.length === 4, "terminal history must respect retention bound");

  return {
    vulnerableAccepted: vulnerable.jobs.length,
    vulnerableUnique: new Set(vulnerable.jobs.map((job) => job.id)).size,
    serialCount: serialOrder.length,
    fixed: {
      duplicate: duplicateBatch[1].reason,
      aliasAccepted: duplicateBatch.filter((result) => result.accepted).length,
      crossPrincipal: crossPrincipal.reason,
      fullQueue: fullRejection.reason,
      completionRetry: retry.accepted,
      rate: rateRejection.reason,
      rateAfterExpiry: rateAfterExpiry.accepted,
      concurrency: blockedStart.reason,
      retention: retentionQueue.terminal.length,
    },
  };
}

function main() {
  const { sourceRoot, labRoot } = validateOwnership(process.argv[2], process.argv[3]);
  const sources = readPinnedSources(sourceRoot);
  inspectSource(sources);
  const aliasCount = runAuthorizationMatrix();
  const metrics = runQueueModels();
  assert(readdirSync(labRoot).length === 0, "probe must leave the laboratory empty");

  console.log(`[+] exact_source_fingerprints_verified=${sources.size}`);
  console.log(`[AUTH] modern_backup_aliases=${aliasCount} admin=allow legacy_backup=deny owner_fresh_required=missing`);
  console.log(`[VULNERABLE] CAN-206 duplicate_requests=8 accepted=${metrics.vulnerableAccepted} unique_jobs=${metrics.vulnerableUnique} queue_depth_bound=absent`);
  console.log(`[SCHEDULER] consumer=serial synthetic_queued=${metrics.serialCount} typed_privileged_execution=source_verified backpressure=absent`);
  console.log("[FIXED-AUTH] modern_aliases=deny_admin database_backup=deny_admin owner_fresh=true");
  console.log(`[FIXED-CONTROL] sequential_alias_dedupe_accepted=${metrics.fixed.aliasAccepted}/2 duplicate=${metrics.fixed.duplicate} full_queue=${metrics.fixed.fullQueue} completion_then_retry=${metrics.fixed.completionRetry ? "allow" : "deny"} cross_principal=${metrics.fixed.crossPrincipal} per_principal=${metrics.fixed.rate} rate_after_expiry=${metrics.fixed.rateAfterExpiry ? "allow" : "deny"} concurrency=${metrics.fixed.concurrency} retention=${metrics.fixed.retention} atomic_race=NOT_TESTED`);
  console.log("[SAFE] source_reads=9 synthetic_fixture=in_memory real_jobs_queued=0 real_jobs_executed=0 network_calls=0 service_starts=0 live_state_reads=0 lab_writes=0");
  console.log("[+] result=VULNERABLE");
}

try {
  main();
} catch (error) {
  console.error(`[!] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}
