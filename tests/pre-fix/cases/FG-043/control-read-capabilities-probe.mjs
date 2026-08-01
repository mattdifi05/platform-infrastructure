#!/usr/bin/env node

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const REVISION = "68cd05895b8d479ffb8167344282e7d922958bfc";
const EXPECTED_HASHES = new Map([
  ["control-center/auth/oidc.mjs", "2f0c9ea5239935857caab3f233ff43cdb81a34d8ab77cfc1a7a00c2a1b7b91b1"],
  ["control-center/server.mjs", "0e660c3278ebe6d85c83e6852ef0afee6be10e7a434c3b37f0f33154969549b6"],
  ["control-center/AUTHENTICATION.md", "1e22e3474fe4cde9711c0e4d2a0aabdb3bf74e12dc1415cb4f9915f28f3b9bda"],
]);

const [mode, sourceArgument, runRootArgument, wrapperRootArgument, sentinelArgument] = process.argv.slice(2);
if (!mode || !sourceArgument || !runRootArgument || !wrapperRootArgument || !sentinelArgument) {
  throw new Error("direct invocation denied: use run-from-git-archive.sh with its wrapper-owned archive");
}
assert.ok(mode === "guard" || mode === "run", "mode must be guard or run");

const wrapperRoot = exactPhysicalDirectory(wrapperRootArgument, "wrapper root");
const runRoot = exactPhysicalDirectory(runRootArgument, "run root");
assert.equal(path.dirname(runRoot), wrapperRoot, "run root must be an exact child of the wrapper root");
assert.match(path.basename(runRoot), mode === "guard" ? /^guard\.[A-Za-z0-9]+$/ : /^run\.[A-Za-z0-9]+$/);
const sourceRoot = exactPhysicalDirectory(sourceArgument, "source archive");
assert.equal(sourceRoot, path.join(runRoot, "source"), "source archive must be the exact real source child");

const sentinelPath = path.resolve(sentinelArgument);
const sentinelStat = fs.lstatSync(sentinelPath);
assert.equal(sentinelStat.isFile(), true, "wrapper ownership sentinel is not a regular file");
assert.equal(sentinelStat.isSymbolicLink(), false, "wrapper ownership sentinel is a symbolic link");
assert.equal(fs.realpathSync(sentinelPath), sentinelPath, "wrapper ownership sentinel must use its physical path");
assert.equal(path.dirname(sentinelPath), wrapperRoot, "wrapper ownership sentinel escaped the wrapper root");
const sentinelMatch = path.basename(sentinelPath).match(/^\.fg043-wrapper-owner-([0-9a-f]{64})$/);
assert.ok(sentinelMatch, "wrapper ownership sentinel name is invalid");
const ownerToken = sentinelMatch[1];
assert.equal(
  fs.readFileSync(sentinelPath, "utf8"),
  `fg043-read-capabilities:${ownerToken}\n`,
  "wrapper ownership sentinel content is invalid",
);

for (const [relativePath, expectedHash] of EXPECTED_HASHES) {
  assert.equal(sha256File(path.join(sourceRoot, relativePath)), expectedHash, `${relativePath} is not the expected source`);
}

const outputRoot = path.join(runRoot, "poc-output");
if (fs.existsSync(outputRoot)) {
  throw new Error("refusing to overwrite pre-existing output target: poc-output");
}
if (mode === "guard") {
  throw new Error("guard mode requires a pre-existing output target");
}

const outputOwnership = claimOwnedDirectory(outputRoot, runRoot, ownerToken);
try {
  const oidcSource = readSource("control-center/auth/oidc.mjs");
  const serverSource = readSource("control-center/server.mjs");
  const policySource = readSource("control-center/AUTHENTICATION.md");

  assert.match(policySource, /\| `viewer` \| viewer \| yes \| no \| no \|/);
  assert.match(policySource, /Sensitive operations include Vault access, database administration, backup or\s+restore/);
  assert.match(serverSource, /if \(method === "GET" && route\(parts, "control", "vault"\)\) return json\(res, \{ items: context\.vaultItems/);
  assert.match(serverSource, /if \(method === "GET" && route\(parts, "control", "backups", "files"\)\) return json\(res, readBackupFiles/);
  assert.match(serverSource, /if \(method === "GET" && route\(parts, "control", "backups", "preview"\)\) return json\(res, readBackupPreview/);
  assert.match(serverSource, /if \(parts\[0\] === "control" && parts\[1\] === "v1"\) return \["control", \.\.\.parts\.slice\(2\)\]/);

  const authorizeMethod = extractAuthorizeMethod(oidcSource);
  const sensitiveFunction = extractFunction(
    oidcSource,
    "function isSensitivePath(pathname) {",
    "\n}\n\nfunction normalizeSessionRow",
  );
  const deniedFunction = oidcSource.match(/^function denied\([^\n]+$/m)?.[0] || "";
  assert.ok(deniedFunction, "unable to extract denied()");
  const authorizationContext = vm.createContext({});
  vm.runInContext(`
${deniedFunction}
${sensitiveFunction}
class ExtractedAuth {
  constructor(config) { this.config = config; }
${authorizeMethod}
}
globalThis.ExtractedAuth = ExtractedAuth;
`, authorizationContext, { filename: "extracted-oidc-authorize.mjs" });
  const ExtractedAuth = vm.runInContext("ExtractedAuth", authorizationContext);
  const auth = new ExtractedAuth({ freshAuthSeconds: 300 });

  const now = Date.now();
  const sessions = {
    viewer: session("viewer", now),
    admin: session("admin", now),
    staleOwner: session("owner", now - 301_000),
    freshOwner: session("owner", now),
  };
  const vulnerableRoutes = [
    ["backup_files", "/control/backups/files?path=postgres"],
    ["backup_preview", "/control/backups/preview?path=postgres/latest.dump"],
    ["vault_metadata", "/control/vault"],
  ];
  const vulnerableMatrix = {};
  for (const [label, route] of vulnerableRoutes) {
    vulnerableMatrix[label] = roleMatrix(auth, "GET", route, sessions);
    assert.deepEqual(vulnerableMatrix[label], {
      viewer: 200,
      admin: 200,
      staleOwner: 200,
      freshOwner: 200,
    });
  }

  for (const alias of [
    "/control/v1/backups/files?path=postgres",
    "/control/v1/backups/preview?path=postgres/latest.dump",
    "/control/v1/vault",
  ]) {
    assert.deepEqual(roleMatrix(auth, "GET", alias, sessions), {
      viewer: 200,
      admin: 200,
      staleOwner: 200,
      freshOwner: 200,
    });
  }

  const positiveControls = {
    backupAction: roleMatrix(auth, "POST", "/actions/backup-command", sessions),
    vaultAction: roleMatrix(auth, "POST", "/actions/vault-command", sessions),
  };
  const expectedSensitiveMatrix = { viewer: 403, admin: 403, staleOwner: 428, freshOwner: 200 };
  assert.deepEqual(positiveControls.backupAction, expectedSensitiveMatrix);
  assert.deepEqual(positiveControls.vaultAction, expectedSensitiveMatrix);

  const sanitizeMessageFunction = extractFunction(
    serverSource,
    "function sanitizeMessage(message) {",
    "\n}\n\nfunction sanitizeEvent",
  );
  const previewRedactorFunction = extractFunction(
    serverSource,
    "function redactBackupPreviewText(text) {",
    "\n}\n\nfunction uniqueBackupResources",
  );
  const previewRedactor = vm.runInNewContext(
    `${sanitizeMessageFunction}\n${previewRedactorFunction}\nredactBackupPreviewText`,
    {},
    { filename: "extracted-backup-preview-redactor.mjs" },
  );
  const preview = previewRedactor([
    "recovery_host=db-internal.example.invalid",
    "customer_identifier=tenant-alpha",
    "password=synthetic-password-canary",
  ].join("\n"));
  assert.match(preview.content, /recovery_host=db-internal\.example\.invalid/);
  assert.match(preview.content, /customer_identifier=tenant-alpha/);
  assert.doesNotMatch(preview.content, /synthetic-password-canary/);
  assert.equal(preview.linesRedacted, 1);

  const backupFields = ["name", "path", "type", "sizeBytes", "sizeLabel", "modifiedAt", "browsable", "removable"];
  for (const field of backupFields) {
    assert.match(serverSource, new RegExp(`\\b${field}:`));
  }
  const vaultFields = [
    "itemKey", "label", "projectId", "environment", "kind", "username", "url",
    "rotationDays", "rotationStatus", "valueStored", "fingerprintStored", "source",
    "createdAt", "updatedAt",
  ];
  const vaultRecord = extractFunction(
    serverSource,
    "function vaultItemRecord({",
    "\n}\n\nfunction workerRuntimeRecord",
  );
  for (const field of vaultFields) {
    assert.match(vaultRecord, new RegExp(`\\b${field}\\b`));
  }
  assert.match(vaultRecord, /valueExposed: false/);
  assert.doesNotMatch(vaultRecord, /\bvalue\s*:/);
  assert.match(vaultRecord, /valueFingerprint: includeSealed \? cleanFingerprint : ""/);
  assert.match(vaultRecord, /if \(includeSealed\) clean\.sealedValue/);
  assert.match(serverSource, /\.map\(\(item\) => vaultItemRecord\(item\)\)/);

  const fixedReferenceMatrix = {};
  for (const [label, route] of vulnerableRoutes) {
    fixedReferenceMatrix[label] = referenceCapabilityAuthorize("GET", route, sessions, now);
    assert.deepEqual(fixedReferenceMatrix[label], expectedSensitiveMatrix);
  }
  for (const alias of [
    "/control/v1/backups/files?path=postgres",
    "/control/v1/backups/preview?path=postgres/latest.dump",
    "/control/v1/vault",
  ]) {
    assert.deepEqual(referenceCapabilityAuthorize("GET", alias, sessions, now), expectedSensitiveMatrix);
  }

  const receipt = {
    revision: REVISION,
    result: "VULNERABLE",
    vulnerableMatrix,
    positiveControls,
    fixedReferenceMatrix,
    sourceHashes: Object.fromEntries(EXPECTED_HASHES),
  };
  const receiptPath = path.join(outputRoot, "authorization-matrix.json");
  fs.writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  assert.deepEqual(JSON.parse(fs.readFileSync(receiptPath, "utf8")), receipt);

  console.log("[+] confinement wrapper_realpath_exact=true source_exact_child=true sentinel_valid=true");
  console.log("[+] source hashes oidc=true server=true policy=true");
  console.log("[VULNERABLE] backup_files viewer=200 admin=200 stale_owner=200 fresh_owner=200");
  console.log("[VULNERABLE] backup_preview viewer=200 admin=200 stale_owner=200 fresh_owner=200");
  console.log("[VULNERABLE] vault_metadata viewer=200 admin=200 stale_owner=200 fresh_owner=200");
  console.log("[VULNERABLE] canonical_and_v1_aliases_equivalent=true");
  console.log("[POSITIVE-CONTROL] sensitive_actions viewer=403 admin=403 stale_owner=428 fresh_owner=200");
  console.log("[SINK] backup_inventory_fields=8 vault_metadata_fields=14 preview_nonkeyword_text_survives=true");
  console.log("[NEGATIVE] vault_plaintext_returned=false sealed_value_returned=false password_canary_returned=false");
  console.log("[REFERENCE] explicit_capabilities viewer=403 admin=403 stale_owner=428 fresh_owner=200");
  console.log("[+] safety server_starts=0 idp_calls=0 database_calls=0 backup_reads=0 vault_reads=0 network_attempts=0");
  console.log("[+] result=VULNERABLE");
} finally {
  cleanupOwnedDirectory(outputOwnership);
}

assert.equal(fs.existsSync(outputRoot), false, "sentinel-owned output was not removed");
console.log("[+] cleanup sentinel_owned_output_removed=true");

function readSource(relativePath) {
  return fs.readFileSync(path.join(sourceRoot, relativePath), "utf8");
}

function exactPhysicalDirectory(argument, label) {
  const resolved = path.resolve(argument);
  const stat = fs.lstatSync(resolved);
  assert.equal(stat.isDirectory(), true, `${label} is not a directory`);
  assert.equal(stat.isSymbolicLink(), false, `${label} must not be a symbolic link`);
  const physical = fs.realpathSync(resolved);
  assert.equal(physical, resolved, `${label} argument must be its exact physical path`);
  return physical;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function extractAuthorizeMethod(source) {
  const start = "  authorize(req, url, session) {";
  const end = "\n  }\n\n  async validateMutation";
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, "unable to extract authorize() from OIDC source");
  assert.equal(source.indexOf(start, startIndex + 1), -1, "authorize() extraction is ambiguous");
  return source.slice(startIndex, endIndex + "\n  }".length);
}

function extractFunction(source, start, end) {
  const startIndex = source.indexOf(start);
  const endIndex = source.indexOf(end, startIndex);
  assert.ok(startIndex >= 0 && endIndex > startIndex, `unable to extract ${start}`);
  assert.equal(source.indexOf(start, startIndex + 1), -1, `ambiguous extraction for ${start}`);
  return source.slice(startIndex, endIndex + "\n}".length);
}

function session(role, authTimeMs) {
  return {
    ok: true,
    status: 200,
    message: "",
    role,
    identity: { subject: `synthetic-${role}`, role, authTime: new Date(authTimeMs) },
  };
}

function roleMatrix(auth, method, route, sessions) {
  const req = { method };
  const url = new URL(route, "https://control.example.invalid");
  return Object.fromEntries(Object.entries(sessions).map(([name, value]) => {
    const decision = auth.authorize(req, url, structuredClone(value));
    return [name, decision.ok ? 200 : decision.status];
  }));
}

function canonicalSegments(route) {
  const url = new URL(route, "https://control.example.invalid");
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments[0] === "control" && segments[1] === "v1") return ["control", ...segments.slice(2)];
  return segments;
}

function referenceCapabilityAuthorize(method, route, sessions, now) {
  const segments = canonicalSegments(route);
  const key = `${method.toUpperCase()} /${segments.join("/")}`;
  const sensitiveReads = new Set([
    "GET /control/backups/files",
    "GET /control/backups/preview",
    "GET /control/vault",
  ]);
  assert.equal(sensitiveReads.has(key), true, `reference capability is missing ${key}`);
  return Object.fromEntries(Object.entries(sessions).map(([name, value]) => {
    if (value.role !== "owner") return [name, 403];
    if (now - new Date(value.identity.authTime).getTime() > 300_000) return [name, 428];
    return [name, 200];
  }));
}

function claimOwnedDirectory(targetPath, expectedParent, token) {
  assert.equal(path.dirname(targetPath), expectedParent, "output target escaped its wrapper-owned parent");
  if (fs.existsSync(targetPath)) throw new Error(`refusing pre-existing output target: ${targetPath}`);
  fs.mkdirSync(targetPath, { recursive: false, mode: 0o700 });
  const targetStat = fs.lstatSync(targetPath);
  assert.equal(targetStat.isDirectory(), true);
  assert.equal(targetStat.isSymbolicLink(), false);
  assert.equal(fs.realpathSync(targetPath), targetPath);
  const ownershipSentinel = path.join(targetPath, `.fg043-output-owner-${token}`);
  fs.writeFileSync(ownershipSentinel, `fg043-output:${token}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  const sentinelStat = fs.lstatSync(ownershipSentinel);
  return {
    targetPath,
    targetDevice: targetStat.dev,
    targetInode: targetStat.ino,
    ownershipSentinel,
    sentinelDevice: sentinelStat.dev,
    sentinelInode: sentinelStat.ino,
    token,
  };
}

function cleanupOwnedDirectory(ownership) {
  const targetStat = fs.lstatSync(ownership.targetPath);
  assert.equal(targetStat.isDirectory(), true, "cleanup target is not a directory");
  assert.equal(targetStat.isSymbolicLink(), false, "refusing cleanup through target symlink");
  assert.equal(targetStat.dev, ownership.targetDevice, "refusing cleanup after target device substitution");
  assert.equal(targetStat.ino, ownership.targetInode, "refusing cleanup after target inode substitution");
  const sentinelStat = fs.lstatSync(ownership.ownershipSentinel);
  assert.equal(sentinelStat.isFile(), true, "cleanup sentinel is not a regular file");
  assert.equal(sentinelStat.isSymbolicLink(), false, "cleanup sentinel is a symbolic link");
  assert.equal(sentinelStat.dev, ownership.sentinelDevice, "refusing cleanup after sentinel device substitution");
  assert.equal(sentinelStat.ino, ownership.sentinelInode, "refusing cleanup after sentinel inode substitution");
  assert.equal(
    fs.readFileSync(ownership.ownershipSentinel, "utf8"),
    `fg043-output:${ownership.token}\n`,
    "cleanup sentinel content changed",
  );
  fs.rmSync(ownership.targetPath, { recursive: true, force: false });
}
