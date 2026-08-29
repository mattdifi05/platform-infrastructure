import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const deploySource = fs.readFileSync(path.join(here, "deploy-v1-local-private.sh"), "utf8");
const node = process.env.PLATFORM_TEST_NODE || "node";

// The begin/apply/evidence/seal verifier script embedded in the deploy: it now
// carries the exact canonicalizer (integer lexemes beyond
// Number.MAX_SAFE_INTEGER survive parse+stable byte-identically).
const marker = "--input-type=module -e '";
let beginScript = "";
for (let cursor = deploySource.indexOf(marker); cursor >= 0 && !beginScript; cursor = deploySource.indexOf(marker, cursor + 1)) {
  const closing = deploySource.indexOf("'", cursor + marker.length);
  const candidate = deploySource.slice(cursor + marker.length, closing);
  if (candidate.includes("exactParse") && candidate.includes('kind === "begin"')) beginScript = candidate;
}
if (!beginScript) throw new Error("the exact begin verifier script was not found in the deploy source.");

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string" || typeof value === "number") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
}

function beginDocument() {
  return {
    schema: "platform.v1-local-private-reconciliation/v1",
    status: "RECONCILING",
    candidateCommit: "1".repeat(40),
    candidateTree: "2".repeat(40),
    sourceArchiveSha256: "3".repeat(64),
    releaseRoot: `/srv/platform-infrastructure/releases/${"1".repeat(40)}-${"3".repeat(64)}`,
    releaseAuthorityDocumentId: "4".repeat(64),
    releaseAuthoritySha256: "5".repeat(64),
    rollbackSchedulerRecovery: {
      exportIdentity: { ctimeNs: 1787954334854084405, device: 64513, inode: 791313, mode: 420, uid: 0, gid: 0, size: 94638080 },
      exportSha256: "6".repeat(64),
      recoveryImageId: "sha256:" + "7".repeat(64),
      runningImageId: "sha256:" + "8".repeat(64),
    },
  };
}

function verifierRun(t, document, { raw } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-canonical-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const authority = {
    candidateCommit: document.candidateCommit,
    candidateTree: document.candidateTree,
    sourceArchiveSha256: document.sourceArchiveSha256,
    releaseRoot: document.releaseRoot,
    documentId: document.releaseAuthorityDocumentId,
    renderSha256: "5".repeat(64),
  };
  const authorityFile = path.join(root, "authority.json");
  fs.writeFileSync(authorityFile, `${canonical(authority)}\n`);
  const beginFile = path.join(root, "begin.json");
  fs.writeFileSync(beginFile, raw ?? `${canonical(document)}\n`);
  return execFileSync(node, ["--input-type=module", "-e", beginScript, beginFile, "begin", authorityFile, "5".repeat(64)], {
    encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  });
}

test("begin verifier preserves integer lexemes beyond Number.MAX_SAFE_INTEGER", (t) => {
  const document = beginDocument();
  const raw = `${canonical(document)}\n`;
  assert.doesNotThrow(() => verifierRun(t, document, { raw }));
});

test("begin verifier rejects non-canonical JSON byte drift", (t) => {
  const document = beginDocument();
  const raw = `${canonical(document)}\n`.replace('"RECONCILING"', ' "RECONCILING"');
  assert.throws(() => verifierRun(t, document, { raw }), /not canonical JSON/);
});

test("begin verifier leaves normal integers, strings, booleans, null, arrays and objects byte-identical", (t) => {
  const document = {
    ...beginDocument(),
    rollbackSchedulerRecovery: {
      exportIdentity: { ctimeNs: 1787954334, device: 64513, inode: 791313, mode: 420, uid: 0, gid: 0, size: 94638080 },
      exportSha256: "6".repeat(64),
      recoveryImageId: "sha256:" + "7".repeat(64),
      runningImageId: "sha256:" + "8".repeat(64),
      extras: [true, false, null, 1, -2.5, "text", [], {}],
    },
  };
  assert.doesNotThrow(() => verifierRun(t, document, { raw: `${canonical(document)}\n` }));
});
