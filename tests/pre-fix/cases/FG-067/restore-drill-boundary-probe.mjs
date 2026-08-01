#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const TREE = "70031b30316fbaecbb23249491d6ff4e364d65d5";
const EXPECTED_HASHES = new Map([
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["compose.yaml", "ed630eee1be8350142493307c2647aa98ce67324c93c127a9370a19a24a9d6c7"],
]);

const [mode, sourceArgument, runRootArgument, wrapperArgument, sentinelArgument] = process.argv.slice(2);
if (!mode || !sourceArgument || !runRootArgument || !wrapperArgument || !sentinelArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned archive");
}
assert.ok(mode === "guard" || mode === "run", "mode must be guard or run");

const wrapperRoot = exactPhysicalDirectory(wrapperArgument, "wrapper root");
const runRoot = exactPhysicalDirectory(runRootArgument, "run root");
assert.equal(path.dirname(runRoot), wrapperRoot, "run root must be an exact wrapper child");
assert.match(path.basename(runRoot), mode === "guard" ? /^guard\.[A-Za-z0-9]+$/ : /^run\.[A-Za-z0-9]+$/);

const sourceRoot = exactPhysicalDirectory(sourceArgument, "source archive");
assert.equal(sourceRoot, path.join(wrapperRoot, "source"), "source archive must be the exact wrapper child");

const sentinelPath = path.resolve(sentinelArgument);
const sentinelStat = fs.lstatSync(sentinelPath);
assert.equal(sentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(sentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel is a symbolic link");
assert.equal(fs.realpathSync(sentinelPath), sentinelPath, "wrapper ownership sentinel must use its physical path");
assert.equal(path.dirname(sentinelPath), wrapperRoot, "wrapper ownership sentinel escaped its root");
const sentinelMatch = path.basename(sentinelPath).match(/^\.fg067-wrapper-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(sentinelPath, "utf8"),
  `fg067-restore-boundary:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} is not the expected source`);
}

const outputRoot = path.join(runRoot, "poc-output");
if (fs.existsSync(outputRoot)) {
  throw new Error("refusing to overwrite pre-existing output target: poc-output");
}
if (mode === "guard") {
  throw new Error("guard mode requires a pre-existing output target");
}

const outputOwnership = claimOwnedDirectory(outputRoot, runRoot, ownerToken);
let receiptHash = null;

try {
  const infraSource = readSource("scripts/infra-ops.mjs");
  const composeSource = readSource("compose.yaml");

  const backupPostgresSource = sliceBetween(
    infraSource,
    "async function backupPostgres(options = {}) {",
    "\nfunction applicationSourceBackupExcludes() {",
  );
  const typedBackupSource = sliceBetween(
    infraSource,
    "async function executeTypedBackupResource(resource) {",
    "\nfunction readVerifiedSourceManifest(relativePath) {",
  );
  const typedRestoreSource = sliceBetween(
    infraSource,
    "async function executeTypedRestoreResource(resource, artifact) {",
    "\nasync function executeBackupJob(options = {}) {",
  );
  const postgresRestoreSource = sliceBetween(
    infraSource,
    "async function restoreTestPostgres(options = {}) {",
    "\nasync function backupRestoreDrill() {",
  );
  const scheduledDrillSource = sliceBetween(
    infraSource,
    "async function backupRestoreDrill() {",
    "\nasync function backupMariadb(options = {}) {",
  );
  const mariaRestoreSource = sliceBetween(
    infraSource,
    "async function restoreTestMariadb(options = {}) {",
    "\nfunction countMariadbUserSchemas(container) {",
  );
  const postgresComposeSource = sliceFirstBetween(composeSource, "  postgres:\n", "\n  redis:\n");

  assert.match(backupPostgresSource, /const container = options\.container \?\? argv\.container \?\? "enterprise-postgres"/);
  assert.match(backupPostgresSource, /const user = options\.user \?\? argv\.user \?\? "postgres"/);
  assert.match(backupPostgresSource, /"pg_dump", "-U", user, "-d", database, "--format=custom", "--no-owner", "--no-acl"/);
  assert.match(typedBackupSource, /resource\.kind === "database" && resource\.engine === "postgres"/);
  assert.match(typedBackupSource, /BACKUP_POSTGRES_CONTAINER \|\| "enterprise-postgres"/);
  assert.match(typedBackupSource, /database: resource\.name/);

  assert.match(typedRestoreSource, /resource\.kind === "database" && resource\.engine === "postgres"/);
  assert.match(typedRestoreSource, /restoreTestPostgres\(\{/);
  assert.match(typedRestoreSource, /BACKUP_POSTGRES_CONTAINER \|\| "enterprise-postgres"/);
  assert.match(typedRestoreSource, /database: resource\.name/);
  assert.match(typedRestoreSource, /countAllUserTables: true/);

  assert.match(postgresRestoreSource, /const container = options\.container \?\? argv\.container \?\? "enterprise-postgres"/);
  assert.match(postgresRestoreSource, /const user = options\.user \?\? argv\.user \?\? "postgres"/);
  assert.match(postgresRestoreSource, /create database \$\{testDatabaseIdentifier\}/);
  assert.match(postgresRestoreSource, /"pg_restore", "-U", user, "-d", testDatabase, "--no-owner", "--no-acl", containerPath/);
  assert.match(postgresRestoreSource, /drop database if exists \$\{testDatabaseIdentifier\} with \(force\)/);
  assert.doesNotMatch(postgresRestoreSource, /"--network"/);
  assert.doesNotMatch(postgresRestoreSource, /\["run", "-d", "--name"/);

  assert.match(scheduledDrillSource, /const container = argv\.container \?\? "enterprise-postgres"/);
  assert.match(scheduledDrillSource, /const user = argv\.user \?\? "postgres"/);
  assert.match(scheduledDrillSource, /backupPostgres\(\{ container, database, user, outputDir \}\)/);
  assert.match(scheduledDrillSource, /restoreTestPostgres\(\{ container, database, user, backupFile: backup\.hostPath, testDatabase \}\)/);

  assert.match(postgresComposeSource, /container_name: enterprise-postgres/);
  assert.match(postgresComposeSource, /POSTGRES_USER: \$\{POSTGRES_SUPERUSER:-postgres\}/);
  assert.match(postgresComposeSource, /enterprise_postgres_data:\/var\/lib\/postgresql/);
  assert.match(postgresComposeSource, /- enterprise_net/);

  assert.match(mariaRestoreSource, /Starting disposable MariaDB restore-test container/);
  assert.match(mariaRestoreSource, /run\("docker", \["run", "-d", "--name", drillContainer, "--network", "none"/);
  assert.match(mariaRestoreSource, /finally \{/);
  assert.match(mariaRestoreSource, /run\("docker", \["rm", "-f", drillContainer\]/);

  const sourceFacts = Object.freeze({
    applicationDatabaseSelectedByTypedResource: true,
    backupContainer: "enterprise-postgres",
    backupRole: "postgres",
    dumpFormat: "custom",
    restoreContainer: "enterprise-postgres",
    restoreRole: "postgres",
    ownershipCommandsSuppressed: true,
    aclCommandsSuppressed: true,
    createsDatabaseInsideTargetCluster: true,
    dropsOnlyTestDatabase: true,
    targetHasPersistentLiveVolume: true,
    targetJoinsPlatformNetwork: true,
    postgresDisposableContainerCreated: false,
    mariaDisposableContainerCreated: true,
    mariaNetworkMode: "none",
    mariaWholeContainerCleanupInFinally: true,
  });

  const archiveObject = Object.freeze({
    objectKind: "function-metadata-only",
    sourceOwner: "application_owner",
    securityDefiner: true,
    archivedAclApplied: false,
    defaultExecuteEligible: true,
    bodyPresent: false,
  });
  assert.equal(Object.hasOwn(archiveObject, "sql"), false);
  assert.equal(Object.hasOwn(archiveObject, "command"), false);
  assert.equal(archiveObject.bodyPresent, false);

  const restoredObject = applyNoOwnerRestore(archiveObject, sourceFacts.restoreRole);
  assert.equal(restoredObject.restoredOwner, "postgres");
  assert.equal(restoredObject.potentialDefinerAuthority, "postgres");
  assert.equal(restoredObject.authorityRebound, true);

  const affectedPlan = Object.freeze({
    liveClusterIdentity: "enterprise-postgres",
    targetClusterIdentity: sourceFacts.restoreContainer,
    disposableCluster: sourceFacts.postgresDisposableContainerCreated,
    restoreRole: { name: sourceFacts.restoreRole, superuser: true, administrativeAttributes: ["SUPERUSER"] },
    networkMode: "enterprise_net",
    liveMounts: ["enterprise_postgres_data"],
    secretMounts: [],
    clientAccess: "platform-network-clients",
    cleanup: "drop-test-database",
  });
  const affectedDecision = evaluateRestorePlan(affectedPlan);
  assert.equal(affectedDecision.decision, "rejected");
  assert.deepEqual(affectedDecision.reasons, [
    "target-is-live-cluster",
    "cluster-is-not-disposable",
    "restore-role-is-superuser",
    "restore-role-has-administrative-attributes",
    "network-is-not-none",
    "live-mount-present",
    "client-access-is-not-validator-only",
    "cleanup-does-not-destroy-cluster",
  ]);

  const fixedPlan = Object.freeze({
    liveClusterIdentity: "enterprise-postgres",
    targetClusterIdentity: "offline-disposable-postgres",
    disposableCluster: true,
    restoreRole: { name: "offline_restore_limited", superuser: false, administrativeAttributes: [] },
    networkMode: "none",
    liveMounts: [],
    secretMounts: [],
    clientAccess: "validator-only",
    cleanup: "destroy-cluster",
  });
  const fixedDecision = evaluateRestorePlan(fixedPlan);
  assert.deepEqual(fixedDecision, { decision: "accepted", reasons: [] });

  const partialFixPlan = Object.freeze({
    ...fixedPlan,
    targetClusterIdentity: fixedPlan.liveClusterIdentity,
  });
  const partialFixDecision = evaluateRestorePlan(partialFixPlan);
  assert.equal(partialFixDecision.decision, "rejected");
  assert.deepEqual(partialFixDecision.reasons, ["target-is-live-cluster"]);

  const syntheticLiveState = Object.freeze({
    systemIdentifier: "synthetic-live-cluster-identity",
    selectedDataDigest: "synthetic-live-data-unchanged",
  });
  const syntheticBefore = sha256Json(syntheticLiveState);
  const syntheticAfter = sha256Json(syntheticLiveState);
  assert.equal(syntheticAfter, syntheticBefore);

  const generatedAt = new Date().toISOString();
  const receipt = {
    schema: "restore-drill-privilege-isolation-poc/v1",
    generatedAt,
    finding: "CAN-201",
    input: {
      revision: REVISION,
      tree: TREE,
      archiveSha256: process.env.FG067_ARCHIVE_SHA256 ?? null,
    },
    sourceHashes: Object.fromEntries(EXPECTED_HASHES),
    sourceFacts,
    ownershipTransition: {
      objectKind: archiveObject.objectKind,
      bodyPresent: archiveObject.bodyPresent,
      ownerBefore: archiveObject.sourceOwner,
      ownerAfter: restoredObject.restoredOwner,
      securityDefiner: restoredObject.securityDefiner,
      potentialDefinerAuthority: restoredObject.potentialDefinerAuthority,
      authorityRebound: restoredObject.authorityRebound,
    },
    controls: {
      affectedPlan: affectedDecision,
      restrictedRoleButLiveCluster: partialFixDecision,
      fixedPlan: fixedDecision,
    },
    closure: {
      kind: "synthetic-model-only",
      beforeSha256: syntheticBefore,
      afterSha256: syntheticAfter,
      unchanged: syntheticBefore === syntheticAfter,
    },
    liveExploitation: "NOT-TESTED",
    safety: {
      dockerCalls: 0,
      databaseConnections: 0,
      restores: 0,
      sqlPayloads: 0,
      networkCalls: 0,
      secretReads: 0,
      sourceMutations: 0,
    },
    result: "VULNERABLE-SOURCE-PATH",
  };
  const receiptPath = path.join(outputRoot, "restore-drill-boundary-receipt.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  assert.deepEqual(JSON.parse(fs.readFileSync(receiptPath, "utf8")), receipt);
  receiptHash = sha256File(receiptPath);

  console.log("[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true");
  console.log("[+] source_hashes infra_ops=true compose=true");
  console.log("[SOURCE] postgres_backup_application_content=true restore_target_live_cluster=true restore_role_superuser=true");
  console.log("[SOURCE] maria_comparison_disposable_container=true maria_network_none=true maria_finally_cleanup=true");
  console.log("[VULNERABLE] owner_before=application_owner owner_after=postgres security_definer_authority_rebound=true");
  console.log("[NEGATIVE-CONTROL] restricted_role_but_live_cluster=REJECTED");
  console.log("[FIXED-CONTROL] isolated_cluster=true restricted_role=true network_none=true live_mounts=0 decision=ACCEPTED");
  console.log("[CLOSURE] synthetic_live_cluster_fingerprint_unchanged=true");
  console.log(`[RECEIPT] generated_at=${generatedAt} sha256=${receiptHash}`);
  console.log("[+] result=VULNERABLE-SOURCE-PATH live_exploitation=NOT-TESTED");
  console.log("[+] safety docker_calls=0 database_connections=0 restores=0 sql_payloads=0 network_calls=0 source_mutations=0");
} finally {
  cleanupOwnedDirectory(outputOwnership);
}

assert.match(receiptHash ?? "", /^[a-f0-9]{64}$/);
assert.equal(fs.existsSync(outputRoot), false, "sentinel-owned output was not removed");
console.log("[+] cleanup sentinel_owned_output_removed=true");

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function sliceBetween(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `unable to slice ${start}`);
  assert.equal(source.indexOf(start, startIndex + start.length), -1, `ambiguous slice start for ${start}`);
  return source.slice(startIndex, endIndex);
}

function sliceFirstBetween(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `unable to slice ${start}`);
  return source.slice(startIndex, endIndex);
}

function applyNoOwnerRestore(object, restoreRole) {
  assert.equal(object.bodyPresent, false, "PoC object must remain metadata only");
  assert.equal(typeof restoreRole, "string");
  return Object.freeze({
    ...object,
    restoredOwner: restoreRole,
    potentialDefinerAuthority: object.securityDefiner ? restoreRole : "caller",
    authorityRebound: object.securityDefiner && object.sourceOwner !== restoreRole,
  });
}

function evaluateRestorePlan(plan) {
  const reasons = [];
  if (plan.targetClusterIdentity === plan.liveClusterIdentity) reasons.push("target-is-live-cluster");
  if (plan.disposableCluster !== true) reasons.push("cluster-is-not-disposable");
  if (plan.restoreRole.superuser !== false) reasons.push("restore-role-is-superuser");
  if (plan.restoreRole.administrativeAttributes.length !== 0) reasons.push("restore-role-has-administrative-attributes");
  if (plan.networkMode !== "none") reasons.push("network-is-not-none");
  if (plan.liveMounts.length !== 0) reasons.push("live-mount-present");
  if (plan.secretMounts.length !== 0) reasons.push("secret-mount-present");
  if (plan.clientAccess !== "validator-only") reasons.push("client-access-is-not-validator-only");
  if (plan.cleanup !== "destroy-cluster") reasons.push("cleanup-does-not-destroy-cluster");
  return { decision: reasons.length === 0 ? "accepted" : "rejected", reasons };
}

function exactPhysicalDirectory(argument, label) {
  const resolved = path.resolve(argument);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  const physical = fs.realpathSync(resolved);
  assert.equal(physical, resolved, `${label} argument must be its exact physical path`);
  return physical;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function sha256Json(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function claimOwnedDirectory(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "output target escaped its expected parent");
  assert.equal(fs.existsSync(targetPath), false, "output target already exists");
  fs.mkdirSync(targetPath, { mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true);
  assert.equal(targetStat.isSymbolicLink(), false);
  assert.equal(fs.realpathSync(targetPath), targetPath);
  const ownershipSentinel = path.join(targetPath, `.fg067-output-owner-${token}`);
  fs.writeFileSync(ownershipSentinel, `fg067-output:${token}\n`, { mode: 0o600, flag: "wx" });
  const innerSentinelStat = fs.lstatSync(ownershipSentinel);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    ownershipSentinel,
    sentinelDevice: innerSentinelStat.dev,
    sentinelInode: innerSentinelStat.ino,
    token,
  };
}

function cleanupOwnedDirectory(ownership) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through target symlink");
  assert.equal(fs.realpathSync(ownership.targetPath), ownership.targetPath, "cleanup target physical path changed");
  assert.equal(targetStat.dev, ownership.targetDevice, "cleanup target device changed");
  assert.equal(targetStat.ino, ownership.targetInode, "cleanup target inode changed");

  const innerStat = fs.lstatSync(ownership.ownershipSentinel);
  assert.equal(innerStat.isFile(), true, "output ownership sentinel is not a file");
  assert.equal(innerStat.isSymbolicLink(), false, "output ownership sentinel is a symlink");
  assert.equal(innerStat.dev, ownership.sentinelDevice, "output ownership sentinel device changed");
  assert.equal(innerStat.ino, ownership.sentinelInode, "output ownership sentinel inode changed");
  assert.equal(
    fs.readFileSync(ownership.ownershipSentinel, "utf8"),
    `fg067-output:${ownership.token}\n`,
    "output ownership sentinel content changed",
  );

  const permittedEntries = new Set([
    path.basename(ownership.ownershipSentinel),
    "restore-drill-boundary-receipt.json",
  ]);
  for (const entry of fs.readdirSync(ownership.targetPath)) {
    assert.equal(permittedEntries.has(entry), true, `unexpected cleanup entry: ${entry}`);
    const entryPath = path.join(ownership.targetPath, entry);
    assert.equal(fs.lstatSync(entryPath).isSymbolicLink(), false, `refusing cleanup of symlink: ${entry}`);
  }

  fs.rmSync(ownership.targetPath, { recursive: true });
}
