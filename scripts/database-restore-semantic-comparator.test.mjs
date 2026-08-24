#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const source = fs.readFileSync(path.resolve(import.meta.dirname, "infra-ops.mjs"), "utf8");

function body(start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex + start.length);
  assert.notEqual(startIndex, -1, `missing ${start}`);
  assert.notEqual(endIndex, -1, `missing ${end}`);
  return source.slice(startIndex, endIndex);
}

test("PostgreSQL restore test binds two full deterministic independent restores of one artifact", () => {
  const fingerprint = body("function postgresSemanticFingerprint", "function semanticComparatorReceipt");
  assert.match(fingerprint, /postgresCanonicalSchemaDigest/);
  assert.match(fingerprint, /postgresRelationIdentities\(container, database, user, \["r", "m"\]\)/);
  assert.match(fingerprint, /to_jsonb\(platform_row\)::text[\s\S]*collate \\"C\\"/);
  assert.match(fingerprint, /set timezone = 'UTC'/);
  assert.match(fingerprint, /set search_path = pg_catalog/);
  assert.match(fingerprint, /\["S"\][\s\S]*last_value::text[\s\S]*is_called::text/);
  assert.match(fingerprint, /pg_largeobject_metadata[\s\S]*pg_largeobject/);
  assert.match(fingerprint, /encode\(l\.data, 'hex'\)/);
  assert.match(fingerprint, /structureSha256[\s\S]*rowDataSha256[\s\S]*sequencesSha256[\s\S]*largeObjectsSha256[\s\S]*combinedSha256/);

  const restore = body("async function restoreTestPostgres", "async function backupRestoreDrill");
  const typedPlan = body("function evidencePostgresRestoreSandboxPlan", "async function restorePostgresArtifactSandbox");
  assert.match(typedPlan, /image !== process\.env\.POSTGRES_RESTORE_TEST_IMAGE/);
  assert.match(typedPlan, /"--network", "none"/);
  assert.match(typedPlan, /"--read-only"/);
  assert.match(typedPlan, /"--cap-drop", "ALL"/);
  assert.match(typedPlan, /"-v", backupMount/);
  assert.match(restore, /restorePostgresArtifactSandbox\([\s\S]*firstSandboxContainer/);
  assert.match(restore, /restorePostgresArtifactSandbox\([\s\S]*secondSandboxContainer/);
  assert.doesNotMatch(restore, /postgresSemanticFingerprint\(sourceContainer/);
  assert.match(restore, /semanticComparatorReceipt\("postgres", firstRestore\.fingerprint, secondRestore\.fingerprint\)/);
  assert.match(restore, /if \(!semanticComparator\.matched\)[\s\S]*independent restore mismatch/);
  assert.match(restore, /metadata:[\s\S]*semanticComparator/);
  assert.match(restore, /firstRestoreComparatorSha256:[\s\S]*secondRestoreComparatorSha256:/);
});

test("PostgreSQL canonical structure removes only volatile dump envelope lines", () => {
  const schema = body("function postgresCanonicalSchemaDigest", "function decodeHexIdentifier");
  assert.match(schema, /pg_dump[\s\S]*--schema-only[\s\S]*--no-owner[\s\S]*--no-acl[\s\S]*--quote-all-identifiers/);
  assert.match(schema, /\\\\restrict/);
  assert.match(schema, /\\\\unrestrict/);
  assert.match(schema, /\^-- Dumped/);
  assert.doesNotMatch(schema, /--no-comments|--exclude-table|--exclude-schema/);
});

test("MariaDB restore test compares exact schema set, complete structure, and canonical rows across two isolated restores", () => {
  const fingerprint = body("function mariadbSemanticFingerprint", "async function restoreTestMariadb");
  assert.match(fingerprint, /mariadbCanonicalStructureDigest/);
  assert.match(fingerprint, /mariadbRelationIdentities/);
  assert.match(fingerprint, /octet_length[\s\S]*hex\(/i);
  assert.match(fingerprint, /concat_ws\('\|'[\s\S]*order by binary platform_row/);
  assert.match(fingerprint, /schemaSetSha256[\s\S]*structureSha256[\s\S]*rowDataSha256[\s\S]*combinedSha256/);

  const structure = body("function mariadbCanonicalStructureDigest", "function mariadbRelationIdentities");
  assert.match(structure, /mariadb-dump[\s\S]*--no-data[\s\S]*--routines[\s\S]*--events[\s\S]*--triggers/);
  assert.match(structure, /--single-transaction[\s\S]*--skip-comments[\s\S]*--skip-dump-date/);

  const restore = body("async function restoreTestMariadb", "function countMariadbUserSchemas");
  assert.match(restore, /restoreMariadbArtifactSandbox\([\s\S]*firstDrillContainer/);
  assert.match(restore, /restoreMariadbArtifactSandbox\([\s\S]*secondDrillContainer/);
  assert.doesNotMatch(restore, /mariadbUserSchemas\(sourceContainer/);
  assert.match(restore, /semanticComparatorReceipt\("mariadb", firstRestore\.fingerprint, secondRestore\.fingerprint\)/);
  assert.match(restore, /if \(!semanticComparator\.matched\)[\s\S]*independent restore mismatch/);
  assert.match(restore, /metadata:[\s\S]*semanticComparator/);
  assert.match(restore, /firstRestoreComparatorSha256:[\s\S]*secondRestoreComparatorSha256:/);

  const sandbox = body("async function restoreMariadbArtifactSandbox", "async function restoreTestMariadb");
  assert.match(sandbox, /--tmpfs[\s\S]*\/var\/lib\/mysql/);
  assert.match(sandbox, /rm", "-f", "-v"/);
});

test("typed restore evidence propagates comparator hashes instead of collapsing to counts", () => {
  const typed = body("async function executeTypedRestoreResource", "async function executeBackupJob");
  const postgres = typed.slice(typed.indexOf('resource.engine === "postgres"'), typed.indexOf('resource.engine === "mariadb"'));
  const mariadb = typed.slice(typed.indexOf('resource.engine === "mariadb"'), typed.indexOf('resource.externalId === "minio-data"'));
  for (const [label, restore] of [["postgres", postgres], ["mariadb", mariadb]]) {
    assert.match(restore, /semanticComparator: result\.semanticComparator/, `${label} semantic comparator`);
    assert.match(restore, /firstRestoreComparatorSha256: result\.firstRestoreComparatorSha256/, `${label} first restore comparator hash`);
    assert.match(restore, /secondRestoreComparatorSha256: result\.secondRestoreComparatorSha256/, `${label} second restore comparator hash`);
  }
  assert.match(mariadb, /database: resource\.name/);
});

test("comparator receipt states artifact repeatability scope and never claims later-live source equality", () => {
  const receipt = body("function semanticComparatorReceipt", "async function restorePostgresArtifactSandbox");
  assert.match(receipt, /scope: "same-artifact-independent-double-restore"/);
  assert.match(receipt, /firstRestoreSha256[\s\S]*secondRestoreSha256/);
  assert.doesNotMatch(receipt, /sourceSha256|restoredSha256/);
});

test("closed V1 receipt flag emits one stable canonical prefixed JSON line", () => {
  const helper = body("function v1EvidenceReceiptEnabled", "function parseCanonicalFileDigest");
  assert.match(helper, /argv\.v1EvidenceReceipt !== "true"/);
  assert.match(helper, /schema: "platform\.v1\.restore-evidence-receipt\/v1"/);
  assert.match(helper, /V1_EVIDENCE_RECEIPT:\$\{canonicalComparatorJson\(receipt\)\}/);
  assert.match(helper, /artifactSha256[\s\S]*matched[\s\S]*scope[\s\S]*semanticComparator[\s\S]*counts/);
  for (const operation of ["postgres", "mariadb", "minio", "keycloak"]) {
    assert.match(source, new RegExp(`emitV1EvidenceReceipt\\(\"restore-test-${operation}\"`));
  }
});

test("closed V1 artifact resolver admits only root-owned snapshots under the exact root-bound typed action", () => {
  const invocation = body("const typedEvidenceActionToOperation", "function parseCronTime");
  assert.match(invocation, /typedEvidenceEnvironmentKeys/);
  assert.match(invocation, /Object\.keys\(process\.env\)\.sort\(\)/);
  assert.match(invocation, /process\.getuid\(\) !== 0/);
  assert.match(invocation, /typedEvidenceActionToOperation\[action\]/);
  assert.match(invocation, /\/dev\/shm\/platform-v1-evidence-\$\{runId\}-transaction\/artifact-staging/);
  assert.match(invocation, /sameStringArray\(process\.argv\.slice\(2\), expectedCli\)/);
  assert.doesNotMatch(invocation, /INFRA_DOCKER|canonicalExecutorJson|PLATFORM_V1_EVIDENCE_EXECUTOR_FD|fstatSync\(4\)/);

  const helper = body("function assertRootOwnedPrivateDirectory", "function emitV1EvidenceReceipt");
  assert.match(helper, /assertV1TypedEvidenceCapability/);
  assert.match(helper, /typedEvidenceInvocation\.operation !== expectedOperation/);
  assert.match(helper, /PLATFORM_V1_EVIDENCE_INFRA_OPERATION !== expectedOperation/);
  assert.match(helper, /command !== expectedOperation/);
  assert.match(helper, /process\.getuid\(\) !== 0/);
  assert.match(helper, /metadata\.uid !== 0[\s\S]*0o700/);
  assert.match(helper, /metadata\.nlink !== 1[\s\S]*0o400/);
  assert.match(helper, /O_NOFOLLOW/);
  assert.match(helper, /components\.length !== 2/);
  assert.match(helper, /\.sha256/);
  assert.match(helper, /backupSignatureSidecarPath/);
  for (const operation of ["postgres", "mariadb", "minio", "keycloak"]) {
    assert.match(source, new RegExp(`resolveRestoreTestArtifact\\(backupFileArg, "restore-test-${operation}"\\)`));
  }
});

test("typed root-bound Docker admission rejects raw calls and admits only action-scoped network-none helpers", () => {
  const admission = body("function typedEvidenceTransactionRoot", "function run(bin");
  assert.match(admission, /typedEvidenceDockerExecAllowed/);
  assert.match(admission, /typedEvidenceDockerCopyAllowed/);
  assert.match(admission, /typedEvidenceDockerRunAllowed/);
  assert.match(admission, /args\[0\] !== "run"[\s\S]*--network[\s\S]*"none"/);
  assert.match(admission, /Raw Docker execution is disabled outside the closed typed V1 evidence infra invocation/);
  assert.match(admission, /Docker operation outside its closed action contract/);
  assert.doesNotMatch(admission, /INFRA_DOCKER|arguments:\s*args|writeSync\([^)]*4/);
  const runner = body("function run(bin", "function output(bin");
  assert.match(runner, /assertTypedEvidenceDockerInvocation\(args, options\)/);
  assert.match(runner, /bin = "\/usr\/bin\/docker"/);

  const minioBackup = body("async function backupMinio", "const minioRestoreComparatorVersion");
  const secretBackup = body("async function backupSecretManagerMetadata", "async function restoreTestSecretManagerMetadata");
  const secretRestore = body("async function restoreTestSecretManagerMetadata", "async function backupRestoreDrillSecretManagerMetadata");
  assert.match(minioBackup, /dockerRun\(\[\s*"--network", "none"/);
  assert.match(secretBackup, /dockerRun\(\[\s*"--network", "none"/);
  assert.match(secretRestore, /dockerRun\(\[\s*"--network", "none"/);
  const temp = body("function hostPathForContainerMount", "function dockerStatsSnapshot");
  assert.match(temp, /typedEvidenceTransactionRoot\(\)/);
  assert.match(temp, /path\.join\(transactionRoot \?\? operationsTempRoot, "ops"\)/);
});

test("MinIO compares one isolated durable tree to a stable live source with only the fixed volatile exclusions", () => {
  const probe = body("function minioTreeProbeSource", "function minioVolumeFingerprint");
  assert.match(probe, /stat\.mode & 0o777/);
  assert.match(probe, /sizeBytes: before\.size/);
  assert.match(probe, /stableFileFingerprint/);
  assert.match(probe, /O_NOFOLLOW/);
  assert.match(probe, /sameFileIdentity\(before, after\)[\s\S]*sameFileIdentity\(after, current\)/);
  assert.match(probe, /type: "directory"/);
  assert.match(probe, /\.minio\.sys\/tmp\/\*/);
  assert.match(probe, /\.minio\.sys\/buckets\/\.bloomcycle\.bin\/xl\.meta/);
  assert.match(probe, /\.minio\.sys\/buckets\/\.usage\.json\/xl\.meta/);
  assert.match(probe, /isExcluded\(relative\)/);
  assert.match(probe, /update\(canonical\(entries\)\)/);
  assert.match(source, /function minioLiveSourceFingerprint[\s\S]*--volumes-from/);

  const restore = body("async function restoreTestMinio", "async function backupRestoreDrillMinio");
  assert.match(restore, /sourceBefore = minioLiveSourceFingerprint/);
  assert.match(restore, /restored = extractMinioArtifactVolume/);
  assert.match(restore, /sourceAfter = minioLiveSourceFingerprint/);
  assert.match(restore, /minioTreeComparatorReceipt\(sourceBefore, restored, sourceAfter\)/);
  assert.match(restore, /if \(!semanticComparator\.matched\)[\s\S]*unstable live source/);
  assert.ok(restore.indexOf("minioTreeComparatorReceipt") < restore.indexOf("minio/health/live"), "tree comparison must precede boot health");
  const comparator = body("function minioTreeComparatorReceipt", "async function restoreTestMinio");
  assert.match(comparator, /stable-live-source-before-after-to-isolated-restored-durable-tree/);
  assert.match(comparator, /sourceStable && restoredMatchesSource/);
  assert.match(comparator, /sourceBeforeSha256[\s\S]*restoredSha256[\s\S]*sourceAfterSha256/);
});

test("Keycloak backup confines kcadm state and removes work, config, and log residue", () => {
  const backup = body("async function backupKeycloakConfig", "const keycloakConfigComparatorVersion");
  const program = body("function keycloakBackupProgram", "async function backupKeycloakConfig");
  assert.equal((program.match(/\/opt\/keycloak\/bin\/kcadm\.sh/g) ?? []).length, (program.match(/--config "\$kcadm_config"/g) ?? []).length);
  assert.doesNotMatch(program, /kcadm\.sh[^\n]*\|\| true/);
  assert.match(program, /trap cleanup EXIT/);
  assert.match(program, /rm -rf "\$work" "\$kcadm_config" "\$kcadm_log"/);
  assert.match(program, /default_kcadm_config="\$HOME\/\.keycloak\/kcadm\.config"/);
  assert.match(program, /rm -rf "\$work"[\s\S]*"\$default_kcadm_config"/);
  assert.match(program, /if \[ "\$status" -ne 0 \]; then rm -f "\$archive"; fi/);
  assert.match(program, /keycloakBackupResidueAssertionProgram[\s\S]*test ! -e[\s\S]*\.keycloak\/kcadm\.config/);
  assert.match(backup, /keycloakBackupResidueAssertionProgram\(\)/);
  assert.match(backup, /keycloakBackupCleanupProgram\(\)/);
});

test("Keycloak parses every JSON file and compares canonical content across two isolated extracts", () => {
  const probe = body("function keycloakConfigProbeSource", "function keycloakConfigRestoreFingerprint");
  assert.match(probe, /jsonFiles[\s\S]*for \(const entry of jsonFiles\)[\s\S]*JSON\.parse/);
  assert.match(probe, /canonicalContentSha256/);
  assert.match(probe, /rawJsonSetSha256/);
  assert.match(probe, /archiveTreeSha256/);
  assert.match(probe, /realms\.json must be an array/);

  const restore = body("async function restoreTestKeycloakConfig", "async function backupRestoreDrillKeycloakConfig");
  assert.equal((restore.match(/keycloakConfigRestoreFingerprint\(/g) ?? []).length, 2);
  assert.match(restore, /keycloakConfigComparatorReceipt\(firstRestore, secondRestore\)/);
  assert.match(restore, /if \(!semanticComparator\.matched\)[\s\S]*independent restore mismatch/);
  assert.match(restore, /mode: "double-isolated-config-extract-and-parse"/);
});

test("typed MinIO and Keycloak restore results retain their truthful semantic comparator hashes", () => {
  const typed = body("async function executeTypedRestoreResource", "async function executeBackupJob");
  const minioStart = typed.indexOf('resource.externalId === "minio-data"');
  const keycloakStart = typed.indexOf('resource.externalId === "keycloak-config"');
  assert.notEqual(minioStart, -1);
  assert.notEqual(keycloakStart, -1);
  const minio = typed.slice(minioStart, keycloakStart);
  assert.match(minio, /semanticComparator: result\.semanticComparator/);
  assert.match(minio, /sourceBeforeComparatorSha256: result\.sourceBeforeComparatorSha256/);
  assert.match(minio, /restoredComparatorSha256: result\.restoredComparatorSha256/);
  assert.match(minio, /sourceAfterComparatorSha256: result\.sourceAfterComparatorSha256/);
  const keycloak = typed.slice(keycloakStart, typed.indexOf("resource.kind ===", keycloakStart + 1));
  assert.match(keycloak, /semanticComparator: result\.semanticComparator/);
  assert.match(keycloak, /firstRestoreComparatorSha256: result\.firstRestoreComparatorSha256/);
  assert.match(keycloak, /secondRestoreComparatorSha256: result\.secondRestoreComparatorSha256/);
});
