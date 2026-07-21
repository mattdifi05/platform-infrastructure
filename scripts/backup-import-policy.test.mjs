import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { backupImportConfirmation, validateBackupImportProvenance } from "./backup-import-policy.mjs";

const sha256 = "a".repeat(64);
const provenanceSha256 = "b".repeat(64);
const sourceSystem = "legacy-vps";
const sourceId = "database:platform-postgres-app";
const provenance = {
  schema: "platform.backup-import-provenance/v1",
  createdAt: "2026-07-01T00:00:00.000Z",
  artifact: { fileName: "app.dump", sha256, sizeBytes: 4096 },
  source: { system: sourceSystem, resourceId: sourceId },
};
const valid = {
  artifactName: "app.dump",
  artifactSha256: sha256,
  artifactSizeBytes: 4096,
  provenance,
  provenanceSha256,
  pinnedProvenanceSha256: provenanceSha256,
  expectedSourceSystem: sourceSystem,
  expectedSourceId: sourceId,
  confirmation: backupImportConfirmation({ sha256, sourceSystem, sourceId }),
  now: Date.parse("2026-07-02T00:00:00.000Z"),
};

test("accepts one exact owner-pinned provenance document", () => {
  assert.deepEqual(validateBackupImportProvenance(valid), {
    sourceSystem,
    sourceId,
    createdAt: provenance.createdAt,
    provenanceSha256,
  });
});

test("rejects unsigned, modified, wrong-source, timestamp-only, and future provenance", () => {
  assert.throws(() => validateBackupImportProvenance({ ...valid, pinnedProvenanceSha256: undefined }), /owner-pinned digest/);
  assert.throws(() => validateBackupImportProvenance({ ...valid, artifactSha256: "c".repeat(64) }), /artifact digest mismatch/);
  assert.throws(() => validateBackupImportProvenance({ ...valid, expectedSourceId: "database:other" }), /source identity mismatch/);
  assert.throws(() => validateBackupImportProvenance({ ...valid, provenance: { createdAt: provenance.createdAt } }), /schema/);
  assert.throws(() => validateBackupImportProvenance({ ...valid, provenance: { ...provenance, createdAt: "2099-01-01T00:00:00.000Z" } }), /future/);
  assert.throws(() => validateBackupImportProvenance({ ...valid, confirmation: provenance.createdAt }), /exact confirmation/);
});

test("local secret manager no longer mints backup trust", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const source = fs.readFileSync(path.join(here, "infra-ops.mjs"), "utf8");
  const body = source.match(/async function localSecretManager\(\) \{([\s\S]*?)\n\}/)?.[1] ?? "";
  assert.doesNotMatch(body, /signExistingPostgresBackups/);
  assert.match(source, /Automatic bulk signing is disabled/);
  assert.match(source, /validateBackupImportProvenance\(\{/);
});

