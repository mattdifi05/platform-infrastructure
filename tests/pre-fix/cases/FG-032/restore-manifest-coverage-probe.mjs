#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const EXPECTED_HASHES = new Map([
  ["scripts/infra-ops.mjs", "379d0c79ab22eb4e7210212eb564c173c77b32a89d2e58a87ea4d9158790ac2b"],
  ["control-center/backup/contracts.mjs", "a425629471d4f98af4c0f09ca700d41260207d447adec2f9eb6476148b35450e"],
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["BACKUP-RECOVERY-COVERAGE.md", "c9513da9379ab9ce9cfd0768023f7ac2e0198d45b52029f03d973af636317b05"],
]);

const sourceRoot = path.resolve(process.argv[2] ?? "");
if (!process.argv[2] || !fs.statSync(sourceRoot, { throwIfNoEntry: false })?.isDirectory()) {
  throw new Error("usage: restore-manifest-coverage-probe.mjs /path/to/archived/source");
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

for (const [relativePath, expected] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expected, `${relativePath} is not the expected vulnerable source`);
}
console.log(`[+] verified ${EXPECTED_HASHES.size} embedded vulnerable-source hashes`);

const infraSource = fs.readFileSync(path.join(sourceRoot, "scripts/infra-ops.mjs"), "utf8");
const contractsSource = fs.readFileSync(path.join(sourceRoot, "control-center/backup/contracts.mjs"), "utf8");
const serverSource = fs.readFileSync(path.join(sourceRoot, "control-center/server.mjs"), "utf8");
const coverageDocument = fs.readFileSync(path.join(sourceRoot, "BACKUP-RECOVERY-COVERAGE.md"), "utf8");

assert.match(coverageDocument, /every exact resource has one signed artifact in the same `platform\.backup-manifest\/v1` document/);
assert.match(contractsSource, /missingResourceIds,\s+complete: missingResourceIds\.length === 0/);
assert.match(contractsSource, /Every resource must map to exactly one artifact/);

const uploadSource = sliceBetween(infraSource, "async function offsiteBackupRestic(", "const offsiteRestoreFamilySpecs = [");
assert.match(uploadSource, /latestVerifiedPlatformBackupManifest\(\)/);
assert.match(uploadSource, /new Set\(\[.*manifestPath/s);
assert.match(uploadSource, /for \(const artifact of manifest\.artifacts\)/);

const familySpecsSource = sliceBetween(infraSource, "const offsiteRestoreFamilySpecs = [", "function offsiteRestoreFamilies(");
const discoverySource = sliceBetween(infraSource, "function discoverRestoredBackupArtifacts(", "function stageRestoredBackupArtifact(");
const stagingSource = sliceBetween(infraSource, "function stageRestoredBackupArtifact(", "function offsiteRestoreCoverage(");
const coverageSource = sliceBetween(infraSource, "function offsiteRestoreCoverage(", "function writeOffsiteRestoreDrillReport(");
const restoreSource = sliceBetween(infraSource, "async function offsiteRestoreDrillRestic(", "async function productionPreflight(");
const drSource = sliceBetween(infraSource, "async function drEvidence(", "function listDumpArtifacts(");

assert.match(discoverySource, /restoredFiles\.find\(\(filePath\) => family\.predicate\(filePath\)\)/);
assert.match(stagingSource, /verifyBackupArtifact\(stagedArtifact\)/);
assert.doesNotMatch(stagingSource, /verifyBackupManifestDocument|manifestArtifactForResource|assertRestoreResourceMatchesManifest/);
assert.doesNotMatch(restoreSource, /verifyBackupManifestDocument|manifestArtifactForResource|assertRestoreResourceMatchesManifest/);
assert.match(restoreSource, /discoverRestoredBackupArtifacts\(restoreRoot, families\)/);
assert.match(restoreSource, /family\.restore\(\{ backupFile: staged\.stagedArtifact \}\)/);
assert.match(drSource, /latestOffsiteRestoreCoverage.*offsiteRestoreCoverage/s);
assert.match(drSource, /!latestOffsiteRestoreCoverage\?\.complete/);
assert.match(serverSource, /latestRestoreCoverage\?\.complete === true/);
console.log("[+] static path=exact signed upload manifest -> broad restore-family discovery -> boolean DR consumer");
console.log("[+] nearest control=selected artifact checksum and HMAC; set manifest is not consumed by the restore path");

const syntheticFiles = Object.freeze([
  "backups/postgres/unrelated-admin.dump",
  "backups/postgres/expected-app.dump",
  "backups/mariadb/unrelated-shop.sql.gz",
  "backups/minio/minio-data-old.tar.gz",
  "backups/keycloak/keycloak-config-old.tar.gz",
  "backups/secret-manager/secret-manager-metadata-old.tar.gz",
  "backups/postgres/unexpected-extra.dump",
]);

const sandbox = {
  path,
  listFilesRecursive: () => [...syntheticFiles],
  restoreTestPostgres: () => ({ status: "not-invoked" }),
  restoreTestMariadb: () => ({ status: "not-invoked" }),
  restoreTestMinio: () => ({ status: "not-invoked" }),
  restoreTestKeycloakConfig: () => ({ status: "not-invoked" }),
  restoreTestSecretManagerMetadata: () => ({ status: "not-invoked" }),
};
vm.createContext(sandbox, { name: "restore-manifest-coverage-probe" });
vm.runInContext(`
${familySpecsSource}
${discoverySource}
${coverageSource}
globalThis.probeExports = {
  offsiteRestoreFamilySpecs,
  discoverRestoredBackupArtifacts,
  offsiteRestoreCoverage,
};
`, sandbox, { timeout: 1000 });

const {
  offsiteRestoreFamilySpecs,
  discoverRestoredBackupArtifacts,
  offsiteRestoreCoverage,
} = sandbox.probeExports;
assert.equal(offsiteRestoreFamilySpecs.length, 5);

const discovered = discoverRestoredBackupArtifacts("synthetic-restore-root", offsiteRestoreFamilySpecs);
assert.equal(discovered.postgres, "backups/postgres/unrelated-admin.dump");
assert.equal(discovered.mariadb, "backups/mariadb/unrelated-shop.sql.gz");
assert.equal(Object.values(discovered).filter(Boolean).length, 5);

const familyKeys = offsiteRestoreFamilySpecs.map((family) => family.key);
const acceptedPayload = {
  mode: "restore",
  status: "success",
  allowPartial: false,
  families: [...familyKeys],
  steps: [
    ...familyKeys.map((family) => ({ family, status: "success" })),
    { name: "infra-health", status: "success" },
  ],
};
assert.equal("manifest" in acceptedPayload, false);
assert.equal("manifestId" in acceptedPayload, false);
assert.equal("resourceIds" in acceptedPayload, false);

const acceptedCoverage = offsiteRestoreCoverage(acceptedPayload);
assert.equal(acceptedCoverage.complete, true);
assert.deepEqual([...acceptedCoverage.missingRequiredFamilies], []);

const missingFamilyPayload = {
  ...acceptedPayload,
  steps: acceptedPayload.steps.filter((step) => step.family !== "mariadb"),
};
const missingFamilyCoverage = offsiteRestoreCoverage(missingFamilyPayload);
assert.equal(missingFamilyCoverage.complete, false);

const expectedExactResources = Object.freeze([
  "source:app-alpha",
  "source:app-beta",
  "database:app-alpha",
  "database:app-beta",
  "database:platform-control",
  "database:identity",
  "storage:minio-data",
  "platform-state:keycloak-config",
  "platform-state:control-center-state",
  "platform-state:secret-manager-metadata",
]);
assert.ok(expectedExactResources.length > Object.keys(discovered).length);
assert.equal(familyKeys.includes("source"), false);
assert.equal(familyKeys.includes("control-center-state"), false);

console.log(`[VULNERABLE] manifest_present=false exact_resources=${expectedExactResources.length} family_specimens=${Object.keys(discovered).length} coverage_complete=${acceptedCoverage.complete}`);
console.log(`[VULNERABLE] postgres_selected=${discovered.postgres} expected_exact_database=database:app-alpha`);
console.log(`[VULNERABLE] ignored_extra=${syntheticFiles.at(-1)} exact_set_enforced=false`);
console.log(`[+] negative-control missing_family=mariadb coverage_complete=${missingFamilyCoverage.complete}`);
console.log("[+] safety restore_calls=0 backup_files_read=0 secrets_read=0 services_started=0 network_attempts=0");
console.log("[+] result=VULNERABLE");

function sliceBetween(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.notEqual(start, -1, `missing source marker: ${startMarker}`);
  assert.notEqual(end, -1, `missing source marker: ${endMarker}`);
  assert.ok(end > start, `invalid source marker order: ${startMarker}`);
  return source.slice(start, end);
}
