import assert from "node:assert/strict";
import test from "node:test";

import { resolveAuthorizationCapability } from "../auth/route-capabilities.mjs";

const sensitiveReads = [
  ["/control/vault", "vault.inventory.read"],
  ["/control/backups/summary", "backup.summary.read"],
  ["/control/backups/records", "backup.records.read"],
  ["/control/backups/jobs", "backup.jobs.read"],
  ["/control/backups/files", "backup.files.list"],
  ["/control/backups/preview", "backup.file.preview"],
];

test("FG-043 classifies every Vault and backup read as fresh-owner for canonical and v1 paths", () => {
  for (const [canonicalPath, operationId] of sensitiveReads) {
    for (const pathname of [canonicalPath, canonicalPath.replace("/control/", "/control/v1/")]) {
      const operation = resolveAuthorizationCapability("GET", pathname);
      assert.equal(operation.classified, true, pathname);
      assert.equal(operation.control, true, pathname);
      assert.equal(operation.operationId, operationId, pathname);
      assert.equal(operation.capability, "owner:fresh", pathname);
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

  for (const [pathname] of sensitiveReads) {
    const operation = resolveAuthorizationCapability("POST", pathname);
    assert.equal(operation.classified, false, pathname);
    assert.equal(operation.capability, "deny", pathname);
  }
});
