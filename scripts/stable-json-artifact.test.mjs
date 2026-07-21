#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { snapshotJsonArtifact } from "./stable-json-artifact.mjs";

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "stable-json-artifact-test-"));
process.on("exit", () => fs.rmSync(temporary, { recursive: true, force: true }));

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function assertSwapCannotSplitParseHashAndVerifier(label, approved, forged) {
  const source = path.join(temporary, `${label}.json`);
  const replacement = path.join(temporary, `${label}-replacement.json`);
  const approvedBytes = Buffer.from(`${JSON.stringify(approved)}\n`);
  fs.writeFileSync(source, approvedBytes);
  fs.writeFileSync(replacement, `${JSON.stringify(forged)}\n`);

  const snapshot = snapshotJsonArtifact(source, {
    label,
    afterCapture() {
      fs.renameSync(replacement, source);
    },
  });
  try {
    assert.deepEqual(snapshot.document, approved, `${label} parse must use captured bytes`);
    assert.equal(snapshot.sha256, sha256(approvedBytes), `${label} hash must use captured bytes`);
    assert.deepEqual(JSON.parse(fs.readFileSync(snapshot.snapshotPath, "utf8")), approved, `${label} verifier path must use captured bytes`);
    assert.deepEqual(JSON.parse(fs.readFileSync(source, "utf8")), forged, `${label} hostile pathname swap fixture did not run`);
  } finally {
    snapshot.cleanup();
  }
}

assertSwapCannotSplitParseHashAndVerifier(
  "release-manifest",
  { version: 2, repository: "owner/repo", commitSha: "a".repeat(40), sbom: { sha256: "b".repeat(64) } },
  { version: 2, repository: "attacker/repo", commitSha: "c".repeat(40), sbom: { sha256: "d".repeat(64) } },
);
assertSwapCannotSplitParseHashAndVerifier(
  "release-sbom",
  { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ name: "approved" }] },
  { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ name: "forged" }] },
);

const target = path.join(temporary, "target.json");
const link = path.join(temporary, "link.json");
fs.writeFileSync(target, "{}\n");
fs.symlinkSync(target, link);
assert.throws(() => snapshotJsonArtifact(link), /captured safely/);

process.stdout.write("stable JSON artifact tests passed 3/3\n");
