import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { backupPreviewLimits, safeBackupPreview } from "../backup/preview.mjs";

function fixture(name, body) {
  const root = mkdtempSync(path.join(os.tmpdir(), "backup-preview-"));
  const filePath = path.join(root, name);
  writeFileSync(filePath, body, { mode: 0o600 });
  return { filePath, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("unclassified text with unfamiliar secret names is never rendered", (t) => {
  const secret = "canary-unfamiliar-credential-material";
  const item = fixture("notes.txt", `credential_material=${secret}\nhealthy=true\n`);
  t.after(item.cleanup);
  const result = safeBackupPreview(item.filePath, "postgres/notes.txt");
  assert.equal(result.mode, "metadata-only");
  assert.equal(result.content, "");
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
});

test("valid signature metadata is schema-allowlisted and secret-bearing signature bytes are omitted", (t) => {
  const secret = "canary-signature-material-never-rendered-0000000000000000";
  const item = fixture("artifact.dump.sig.json", `${JSON.stringify({
    version: 1,
    algorithm: "HMAC-SHA256",
    keyId: "backup-v1",
    artifact: "artifact.dump",
    sha256: "a".repeat(64),
    signature: secret,
    signedAt: "2026-07-21T20:00:00.000Z",
  })}\n`);
  t.after(item.cleanup);
  const result = safeBackupPreview(item.filePath, "postgres/artifact.dump.sig.json");
  assert.equal(result.mode, "allowlisted-preview");
  assert.match(result.content, /"signaturePresent": true/);
  assert.doesNotMatch(result.content, /backup-v1|artifact\.dump/);
  assert.doesNotMatch(result.content, new RegExp(secret));
  assert.doesNotMatch(result.content, /"signature":/);
});

test("malformed, unknown-field, binary, and oversized signature files fail closed", (t) => {
  const cases = [
    fixture("malformed.sig.json", '{"version":1,'),
    fixture("unknown.sig.json", JSON.stringify({ credential_material: "canary-unknown-field" })),
    fixture("binary.sig.json", Buffer.from([0xff, 0xfe, 0x00, 0x41])),
    fixture("oversize.sig.json", "x".repeat(backupPreviewLimits.signatureBytes + 1)),
  ];
  for (const item of cases) t.after(item.cleanup);
  for (const item of cases) {
    const result = safeBackupPreview(item.filePath, path.basename(item.filePath));
    assert.equal(result.mode, "metadata-only");
    assert.equal(result.content, "");
    assert.doesNotMatch(JSON.stringify(result), /canary-/);
  }
});

test("checksum preview accepts one exact public record and rejects extra lines", (t) => {
  const acceptedItem = fixture("artifact.dump.sha256", `${"b".repeat(64)}  artifact.dump\n`);
  const rejectedItem = fixture("extra.dump.sha256", `${"b".repeat(64)}  artifact.dump\ncredential_material=canary-extra-line\n`);
  t.after(acceptedItem.cleanup);
  t.after(rejectedItem.cleanup);
  assert.deepEqual(safeBackupPreview(acceptedItem.filePath, "artifact.dump.sha256"), {
    mode: "allowlisted-preview",
    content: JSON.stringify({ sha256: "b".repeat(64), artifactNameMatched: true }, null, 2),
    reason: null,
    message: "Anteprima checksum limitata allo schema pubblico allowlist.",
  });
  const rejected = safeBackupPreview(rejectedItem.filePath, "extra.dump.sha256");
  assert.equal(rejected.mode, "metadata-only");
  assert.equal(rejected.content, "");
  assert.doesNotMatch(JSON.stringify(rejected), /canary-extra-line/);
});
