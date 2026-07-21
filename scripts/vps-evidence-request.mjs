#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256FileBounded } from "./bounded-file-hash.mjs";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));

function invalid(message) {
  throw new Error(message);
}

function exactBoolean(value, label) {
  const text = String(value ?? "");
  if (!["true", "false"].includes(text)) {
    invalid(`${label} must be true or false.`);
  }
  return text;
}

function sshPort(value, label) {
  const text = String(value ?? "");
  const number = Number(text);
  if (!/^\d{1,5}$/.test(text) || !Number.isInteger(number) || number < 1 || number > 65535) {
    invalid(`${label} must be an SSH port between 1 and 65535.`);
  }
  return text;
}

function deployRemote(value) {
  const text = String(value ?? "");
  if (!/^[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(text)) {
    invalid("DEPLOY_REMOTE must be a simple user@hostname value.");
  }
  return text;
}

function remotePath(value) {
  const text = String(value ?? "");
  if (!/^\/[A-Za-z0-9._/-]+$/.test(text) || text.includes("//") || text.split("/").includes("..")) {
    invalid("DEPLOY_REMOTE_DIR must be an absolute path without whitespace, traversal or shell syntax.");
  }
  return text;
}

function optionalDeployUser(value) {
  const text = String(value ?? "");
  if (text && !/^[a-z_][a-z0-9_-]{0,31}$/.test(text)) {
    invalid("DEPLOY_USER must be empty or a valid Unix account name.");
  }
  return text;
}

function gitObjectId(value, label) {
  const text = String(value ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(text)) {
    invalid(`${label} must be an exact 40-character Git object ID.`);
  }
  return text;
}

function sha256(value, label) {
  const text = String(value ?? "").trim().toLowerCase().replace(/^sha256:/, "");
  if (!/^[a-f0-9]{64}$/.test(text)) invalid(`${label} must be an exact SHA-256 digest.`);
  return text;
}

export function validateVpsEvidenceRequest(input) {
  const request = {
    deployRemote: deployRemote(input.DEPLOY_REMOTE),
    remoteDir: remotePath(input.DEPLOY_REMOTE_DIR),
    sshPort: sshPort(input.DEPLOY_SSH_PORT, "DEPLOY_SSH_PORT"),
    hardenedSshPort: sshPort(input.VPS_HARDENED_SSH_PORT, "VPS_HARDENED_SSH_PORT"),
    runBootstrap: exactBoolean(input.RUN_BOOTSTRAP, "RUN_BOOTSTRAP"),
    runHardening: exactBoolean(input.RUN_HARDENING, "RUN_HARDENING"),
    reloadSshd: exactBoolean(input.RELOAD_SSHD, "RELOAD_SSHD"),
    replaceDockerDaemonConfig: exactBoolean(input.REPLACE_DOCKER_DAEMON_CONFIG, "REPLACE_DOCKER_DAEMON_CONFIG"),
    confirmMutatingVps: exactBoolean(input.CONFIRM_MUTATING_VPS, "CONFIRM_MUTATING_VPS"),
    deployUser: optionalDeployUser(input.DEPLOY_USER),
    workflowSha: gitObjectId(input.WORKFLOW_SHA, "WORKFLOW_SHA"),
    workflowTree: gitObjectId(input.WORKFLOW_TREE, "WORKFLOW_TREE"),
  };
  if ((request.runBootstrap === "true" || request.runHardening === "true") && request.confirmMutatingVps !== "true") {
    invalid("CONFIRM_MUTATING_VPS must be true before bootstrap or hardening.");
  }
  return request;
}

function encodedAssignment(name, value) {
  const encoded = Buffer.from(String(value), "utf8").toString("base64");
  return `${name}='${encoded}'`;
}

export function renderVpsEvidenceRemoteScript(request, remoteScriptText) {
  const assignments = [
    encodedAssignment("PLATFORM_REMOTE_DIR_B64", request.remoteDir),
    encodedAssignment("PLATFORM_HARDENED_SSH_PORT_B64", request.hardenedSshPort),
    encodedAssignment("PLATFORM_RUN_BOOTSTRAP_B64", request.runBootstrap),
    encodedAssignment("PLATFORM_RUN_HARDENING_B64", request.runHardening),
    encodedAssignment("PLATFORM_RELOAD_SSHD_B64", request.reloadSshd),
    encodedAssignment("PLATFORM_REPLACE_DOCKER_DAEMON_CONFIG_B64", request.replaceDockerDaemonConfig),
    encodedAssignment("PLATFORM_DEPLOY_USER_B64", request.deployUser),
    encodedAssignment("PLATFORM_WORKFLOW_SHA_B64", request.workflowSha),
    encodedAssignment("PLATFORM_WORKFLOW_TREE_B64", request.workflowTree),
  ];
  return `${assignments.join("\n")}\n${String(remoteScriptText)}`;
}

export function requestFromEnvironment(environment = process.env) {
  return validateVpsEvidenceRequest(environment);
}

export function validateVpsEvidenceArchiveEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) invalid("VPS evidence archive entry list is empty.");
  const normalized = [];
  const seen = new Set();
  for (const raw of entries) {
    const entry = String(raw ?? "").replace(/\/$/, "");
    if (!entry || entry.startsWith("/") || entry.includes("\\") || entry.split("/").includes("..") || /[\0\r\n]/.test(entry)) {
      invalid(`Unsafe VPS evidence archive entry: ${entry || "(empty)"}.`);
    }
    if (!/^reports\/(?:vps-bootstrap|vps-hardening|vps-host)(?:\/[A-Za-z0-9._-]+)*$/.test(entry)) {
      invalid(`Unexpected VPS evidence archive entry: ${entry}.`);
    }
    if (seen.has(entry)) invalid(`Duplicate VPS evidence archive entry: ${entry}.`);
    seen.add(entry);
    normalized.push(entry);
  }
  if (!normalized.some((entry) => /^reports\/vps-host\/.+\.json$/.test(entry))) {
    invalid("VPS evidence archive lacks a host-readiness JSON report.");
  }
  return normalized;
}

export function validateVpsEvidenceReceipt({ receipt, archiveSha256, expectedWorkflowSha, expectedGitTree, nowMs = Date.now() }) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt) || receipt.schema !== "platform.vps-evidence-receipt/v1") {
    invalid("VPS evidence receipt schema is invalid.");
  }
  const workflowSha = gitObjectId(receipt.workflowSha, "Receipt workflow SHA");
  const gitTree = gitObjectId(receipt.gitTree, "Receipt Git tree");
  if (workflowSha !== gitObjectId(expectedWorkflowSha, "Expected workflow SHA")) invalid("VPS evidence receipt workflow SHA mismatch.");
  if (gitTree !== gitObjectId(expectedGitTree, "Expected Git tree")) invalid("VPS evidence receipt Git tree mismatch.");
  if (receipt.checkoutMode !== "detached") invalid("VPS evidence receipt did not use a detached checkout.");
  if (receipt.cleanBefore !== true || receipt.cleanAfter !== true) invalid("VPS evidence receipt worktree was dirty.");
  const expectedArchiveSha256 = sha256(receipt.archiveSha256, "Receipt archive SHA-256");
  if (expectedArchiveSha256 !== sha256(archiveSha256, "Observed archive SHA-256")) invalid("VPS evidence archive digest mismatch.");
  const generatedAt = Date.parse(String(receipt.generatedAt ?? ""));
  if (!Number.isFinite(generatedAt)) invalid("VPS evidence receipt generatedAt is invalid.");
  if (generatedAt > nowMs + 5 * 60 * 1000) invalid("VPS evidence receipt generatedAt is in the future.");
  return {
    status: "passed",
    schema: receipt.schema,
    workflowSha,
    gitTree,
    checkoutMode: "detached",
    cleanBefore: true,
    cleanAfter: true,
    archiveSha256: expectedArchiveSha256,
    generatedAt: new Date(generatedAt).toISOString(),
  };
}

function regularFile(pathValue, label, maxBytes) {
  const resolved = path.resolve(String(pathValue ?? ""));
  const stat = fs.lstatSync(resolved, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink()) invalid(`${label} must be a regular non-symlink file.`);
  if (stat.size <= 0 || stat.size > maxBytes) invalid(`${label} size is invalid.`);
  return resolved;
}

function verifyReceiptCommand(args) {
  const values = {};
  const allowed = new Set(["receipt", "archive", "entries", "expectedSha", "expectedTree"]);
  for (let index = 0; index < args.length; index += 1) {
    const key = args[index];
    const value = args[index + 1];
    if (!key.startsWith("--") || !value || value.startsWith("--")) invalid("verify-receipt requires value-bearing options.");
    const name = key.slice(2);
    if (!allowed.has(name) || Object.hasOwn(values, name)) invalid(`verify-receipt option is unknown or duplicated: ${key}.`);
    values[name] = value;
    index += 1;
  }
  for (const name of allowed) if (!Object.hasOwn(values, name)) invalid(`verify-receipt is missing --${name}.`);
  const receiptPath = regularFile(values.receipt, "Receipt", 64 * 1024);
  const archivePath = regularFile(values.archive, "Archive", 256 * 1024 * 1024);
  const entriesPath = regularFile(values.entries, "Archive entry list", 4 * 1024 * 1024);
  const receipt = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  const archiveSha256 = sha256FileBounded(archivePath, { maxBytes: 256 * 1024 * 1024 }).sha256;
  const entries = fs.readFileSync(entriesPath, "utf8").split("\n").filter(Boolean);
  const provenance = validateVpsEvidenceReceipt({
    receipt,
    archiveSha256,
    expectedWorkflowSha: values.expectedSha,
    expectedGitTree: values.expectedTree,
  });
  const archiveEntries = validateVpsEvidenceArchiveEntries(entries);
  process.stdout.write(`${JSON.stringify({ ...provenance, archiveEntryCount: archiveEntries.length })}\n`);
}

function main() {
  const command = process.argv[2] ?? "render";
  if (command === "verify-receipt") {
    verifyReceiptCommand(process.argv.slice(3));
    return;
  }
  if (command !== "render") {
    invalid("Usage: vps-evidence-request.mjs render [remote-script-path] | verify-receipt --receipt FILE --archive FILE --entries FILE --expectedSha SHA --expectedTree TREE");
  }
  const request = requestFromEnvironment();
  const remoteScriptPath = path.resolve(process.argv[3] ?? path.join(scriptDir, "vps-evidence-remote.sh"));
  const remoteScriptText = fs.readFileSync(remoteScriptPath, "utf8");
  process.stdout.write(renderVpsEvidenceRemoteScript(request, remoteScriptText));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
