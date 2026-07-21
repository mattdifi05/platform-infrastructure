#!/usr/bin/env node
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  renderVpsEvidenceRemoteScript,
  validateVpsEvidenceArchiveEntries,
  validateVpsEvidenceReceipt,
  validateVpsEvidenceRequest,
} from "./vps-evidence-request.mjs";

const valid = {
  DEPLOY_REMOTE: "deploy_user@example.internal",
  DEPLOY_REMOTE_DIR: "/opt/platform-infrastructure",
  DEPLOY_SSH_PORT: "2222",
  VPS_HARDENED_SSH_PORT: "2222",
  RUN_BOOTSTRAP: "false",
  RUN_HARDENING: "false",
  RELOAD_SSHD: "false",
  REPLACE_DOCKER_DAEMON_CONFIG: "false",
  CONFIRM_MUTATING_VPS: "false",
  DEPLOY_USER: "platform_deploy",
  WORKFLOW_SHA: "1".repeat(40),
  WORKFLOW_TREE: "2".repeat(40),
};

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  process.stdout.write(`ok ${passed} - ${name}\n`);
}

test("valid request renders only encoded remote values", () => {
  const request = validateVpsEvidenceRequest(valid);
  const rendered = renderVpsEvidenceRemoteScript(request, "printf done\n");
  assert.ok(!rendered.includes(valid.DEPLOY_USER));
  assert.ok(!rendered.includes(valid.DEPLOY_REMOTE_DIR));
  assert.match(rendered, /^PLATFORM_REMOTE_DIR_B64='[A-Za-z0-9+/=]+'/);
});
test("deploy user command substitution is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_USER: "x$(touch /tmp/pwn)" }), /Unix account/);
});
test("deploy user command separator is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_USER: "valid;id" }), /Unix account/);
});
test("newline injection is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_USER: "valid\nid" }), /Unix account/);
});
test("SSH option injection is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_REMOTE: "-oProxyCommand=id" }), /user@hostname/);
});
test("remote path shell syntax is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_REMOTE_DIR: "/opt/platform;id" }), /absolute path/);
});
test("remote path traversal is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_REMOTE_DIR: "/opt/../root" }), /absolute path/);
});
test("invalid SSH port is rejected", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, DEPLOY_SSH_PORT: "22;id" }), /SSH port/);
});
test("mutation requires explicit confirmation", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, RUN_HARDENING: "true" }), /CONFIRM_MUTATING_VPS/);
});
test("confirmed mutation remains valid", () => {
  const request = validateVpsEvidenceRequest({ ...valid, RUN_HARDENING: "true", CONFIRM_MUTATING_VPS: "true" });
  assert.equal(request.runHardening, "true");
});
test("workflow commit and tree must be exact object IDs", () => {
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, WORKFLOW_SHA: "main" }), /WORKFLOW_SHA/);
  assert.throws(() => validateVpsEvidenceRequest({ ...valid, WORKFLOW_TREE: "2".repeat(39) }), /WORKFLOW_TREE/);
});
test("receipt binds archive to exact detached clean workflow revision", () => {
  const receipt = {
    schema: "platform.vps-evidence-receipt/v1",
    generatedAt: "2026-07-21T12:00:00Z",
    workflowSha: valid.WORKFLOW_SHA,
    gitTree: valid.WORKFLOW_TREE,
    checkoutMode: "detached",
    cleanBefore: true,
    cleanAfter: true,
    archiveSha256: "3".repeat(64),
  };
  const result = validateVpsEvidenceReceipt({ receipt, archiveSha256: receipt.archiveSha256, expectedWorkflowSha: valid.WORKFLOW_SHA, expectedGitTree: valid.WORKFLOW_TREE });
  assert.equal(result.status, "passed");
  for (const mutation of [
    { workflowSha: "4".repeat(40) },
    { gitTree: "5".repeat(40) },
    { checkoutMode: "branch" },
    { cleanBefore: false },
    { cleanAfter: false },
    { archiveSha256: "6".repeat(64) },
    { generatedAt: "2099-01-01T00:00:00Z" },
  ]) {
    assert.throws(() => validateVpsEvidenceReceipt({ receipt: { ...receipt, ...mutation }, archiveSha256: receipt.archiveSha256, expectedWorkflowSha: valid.WORKFLOW_SHA, expectedGitTree: valid.WORKFLOW_TREE }), /mismatch|detached|dirty|digest|future/);
  }
});
test("archive entries are restricted to VPS report roots", () => {
  assert.deepEqual(validateVpsEvidenceArchiveEntries([
    "reports/vps-host/",
    "reports/vps-host/vps-host-readiness-20260721.json",
    "reports/vps-host/vps-host-readiness-20260721.md",
  ]), [
    "reports/vps-host",
    "reports/vps-host/vps-host-readiness-20260721.json",
    "reports/vps-host/vps-host-readiness-20260721.md",
  ]);
  for (const entries of [
    ["/etc/passwd"],
    ["reports/vps-host/../../etc/passwd"],
    ["reports/other/report.json"],
    ["reports/vps-host/report.md"],
    ["reports/vps-host/report.json", "reports/vps-host/report.json"],
  ]) assert.throws(() => validateVpsEvidenceArchiveEntries(entries), /Unsafe|Unexpected|lacks|Duplicate/);
});
test("receipt CLI verifies the returned archive bytes before extraction", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "vps-evidence-receipt-"));
  try {
    const archivePath = path.join(directory, "evidence.tgz");
    const receiptPath = path.join(directory, "receipt.json");
    const entriesPath = path.join(directory, "entries.txt");
    const archiveBytes = Buffer.from("fixture archive bytes");
    fs.writeFileSync(archivePath, archiveBytes);
    fs.writeFileSync(entriesPath, "reports/vps-host/\nreports/vps-host/readiness.json\n");
    fs.writeFileSync(receiptPath, JSON.stringify({
      schema: "platform.vps-evidence-receipt/v1",
      generatedAt: "2026-07-21T12:00:00Z",
      workflowSha: valid.WORKFLOW_SHA,
      gitTree: valid.WORKFLOW_TREE,
      checkoutMode: "detached",
      cleanBefore: true,
      cleanAfter: true,
      archiveSha256: crypto.createHash("sha256").update(archiveBytes).digest("hex"),
    }));
    const args = [path.join(import.meta.dirname, "vps-evidence-request.mjs"), "verify-receipt", "--receipt", receiptPath, "--archive", archivePath, "--entries", entriesPath, "--expectedSha", valid.WORKFLOW_SHA, "--expectedTree", valid.WORKFLOW_TREE];
    const accepted = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).status, "passed");
    fs.appendFileSync(archivePath, "tampered");
    const rejected = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /digest mismatch/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
test("workflow and remote script use exact detached provenance instead of mutable main", () => {
  const root = path.resolve(import.meta.dirname, "..");
  const remote = fs.readFileSync(path.join(import.meta.dirname, "vps-evidence-remote.sh"), "utf8");
  const workflow = fs.readFileSync(path.join(root, ".github", "workflows", "enterprise-vps-evidence.yml"), "utf8");
  assert.match(remote, /worktree add --detach/);
  assert.match(remote, /VPS evidence checkout is dirty before collection/);
  assert.match(remote, /VPS evidence checkout is dirty after collection/);
  assert.doesNotMatch(remote, /git checkout main|git pull --ff-only origin main/);
  assert.match(workflow, /WORKFLOW_SHA: \$\{\{ github\.sha \}\}/);
  assert.match(workflow, /verify-receipt/);
  assert.match(workflow, /--expectedTree/);
});

process.stdout.write(`VPS evidence request tests passed ${passed}/${passed}\n`);
