import assert from "node:assert/strict";
import test from "node:test";

import { resolveAuthorizationCapability } from "../auth/route-capabilities.mjs";

const protectedReads = [
  ["/control/vault", "vault.inventory.read", "owner"],
  ["/control/backups/summary", "backup.summary.read", "owner:fresh"],
  ["/control/backups/records", "backup.records.read", "owner:fresh"],
  ["/control/backups/jobs", "backup.jobs.read", "owner:fresh"],
  ["/control/backups/files", "backup.files.list", "owner:fresh"],
  ["/control/backups/preview", "backup.file.preview", "owner:fresh"],
];

test("Vault metadata requires owner while FG-043 backup reads retain fresh-owner for canonical and v1 paths", () => {
  for (const [canonicalPath, operationId, capability] of protectedReads) {
    for (const pathname of [canonicalPath, canonicalPath.replace("/control/", "/control/v1/")]) {
      const operation = resolveAuthorizationCapability("GET", pathname);
      assert.equal(operation.classified, true, pathname);
      assert.equal(operation.control, true, pathname);
      assert.equal(operation.operationId, operationId, pathname);
      assert.equal(operation.capability, capability, pathname);
      assert.equal(operation.canonicalPath, canonicalPath, pathname);
    }
  }
});

test("FG-043 fails closed for method changes, malformed paths, and unclassified read aliases", () => {
  for (const pathname of [
    "/control/vault/",
    "/control//vault",
    "/control/v1/vault/unknown",
    "/control/backups",
    "/control/v1/backups/preview/extra",
  ]) {
    const operation = resolveAuthorizationCapability("GET", pathname);
    assert.equal(operation.classified, false, pathname);
    assert.equal(operation.capability, "deny", pathname);
  }

  for (const [pathname] of protectedReads) {
    const operation = resolveAuthorizationCapability("POST", pathname);
    assert.equal(operation.classified, false, pathname);
    assert.equal(operation.capability, "deny", pathname);
  }
});
