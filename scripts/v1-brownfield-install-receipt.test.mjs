#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  V1_INSTALL_CANDIDATE_COMMIT,
  V1_INSTALL_CANDIDATE_TREE,
  V1_INSTALL_READY_BUT_DISABLED,
  V1_INSTALL_SOURCE_ARCHIVE_SHA256,
  verifyV1InstallReceipt,
} from "./v1-brownfield-install-receipt.mjs";

const sourceArchiveSha256 = V1_INSTALL_SOURCE_ARCHIVE_SHA256;

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function validReceipt(overrides = {}) {
  return {
    activationAuthorized: false,
    authorizationSource: "ROOT_OPERATOR_EXPLICIT_INSTALL_ONLY",
    backupEvidenceAuthoritative: false,
    candidateCommit: V1_INSTALL_CANDIDATE_COMMIT,
    candidateTree: V1_INSTALL_CANDIDATE_TREE,
    dataMutation: false,
    dockerMutation: false,
    readyButDisabled: [...V1_INSTALL_READY_BUT_DISABLED],
    releaseRoot: `/srv/platform-infrastructure/releases/${V1_INSTALL_CANDIDATE_COMMIT}-${sourceArchiveSha256}`,
    schema: "platform.v1-brownfield-install-receipt/v1",
    sourceArchiveSha256,
    status: "INSTALL_ONLY_COMPLETE",
    ...overrides,
  };
}

function withReceipt(receipt, run, { canonical = true } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-install-receipt-test-"));
  const file = path.join(root, "receipt.json");
  fs.writeFileSync(file, canonical ? `${stableJson(receipt)}\n` : `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  try {
    return run(file);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function verify(file, overrides = {}) {
  return verifyV1InstallReceipt({
    file,
    candidateCommit: V1_INSTALL_CANDIDATE_COMMIT,
    candidateTree: V1_INSTALL_CANDIDATE_TREE,
    sourceArchiveSha256: V1_INSTALL_SOURCE_ARCHIVE_SHA256,
    ...overrides,
  });
}

test("accepts the exact install-only completion receipt", () => {
  withReceipt(validReceipt(), (file) => {
    const receipt = verify(file);
    assert.equal(receipt.status, "INSTALL_ONLY_COMPLETE");
    assert.equal(receipt.activationAuthorized, false);
  });
});

test("accepts an idempotent exact already-installed receipt", () => {
  withReceipt(validReceipt({ status: "ALREADY_INSTALLED" }), (file) => {
    assert.equal(verify(file).status, "ALREADY_INSTALLED");
  });
});

for (const [name, override, pattern] of [
  ["wrong candidate commit", { candidateCommit: "c".repeat(40) }, /candidate commit/],
  ["wrong candidate tree", { candidateTree: "d".repeat(40) }, /candidate tree/],
  ["activation authority", { activationAuthorized: true }, /activationAuthorized/],
  ["caller authorization source", { authorizationSource: "CALLER_ASSERTED" }, /authorization source/],
  ["authoritative backup claim", { backupEvidenceAuthoritative: true }, /non-authoritative/],
  ["Docker mutation", { dockerMutation: true }, /dockerMutation/],
  ["data mutation", { dataMutation: true }, /dataMutation/],
  ["READY_BUT_DISABLED reordering", { readyButDisabled: [...V1_INSTALL_READY_BUT_DISABLED].reverse() }, /READY_BUT_DISABLED/],
  ["release-root mismatch", { releaseRoot: "/srv/platform-infrastructure/releases/attacker" }, /release root/],
  ["invalid archive hash", { sourceArchiveSha256: "A".repeat(64) }, /source archive/],
  ["wrong archive hash", { sourceArchiveSha256: "a".repeat(64) }, /source archive SHA-256/],
]) {
  test(`rejects ${name}`, () => {
    withReceipt(validReceipt(override), (file) => assert.throws(() => verify(file), pattern));
  });
}

test("rejects an unexpected receipt field", () => {
  withReceipt(validReceipt({ authorization: "caller-asserted" }), (file) => {
    assert.throws(() => verify(file), /missing or unexpected fields/);
  });
});

test("rejects non-canonical JSON", () => {
  withReceipt(validReceipt(), (file) => assert.throws(() => verify(file), /not canonical/), { canonical: false });
});

test("rejects a symlink receipt", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "v1-install-receipt-link-test-"));
  const target = path.join(root, "target.json");
  const link = path.join(root, "receipt.json");
  fs.writeFileSync(target, `${stableJson(validReceipt())}\n`, { mode: 0o600 });
  fs.symlinkSync(target, link);
  try {
    assert.throws(() => verify(link), /regular non-symlink/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rejects caller-selected expected candidate values", () => {
  withReceipt(validReceipt(), (file) => {
    assert.throws(() => verify(file, { candidateCommit: "e".repeat(40) }), /Expected candidate commit/);
    assert.throws(() => verify(file, { candidateTree: "f".repeat(40) }), /Expected candidate tree/);
    assert.throws(() => verify(file, { sourceArchiveSha256: "a".repeat(64) }), /Expected source archive/);
  });
});
