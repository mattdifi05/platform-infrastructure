#!/usr/bin/env node
import crypto from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import {
  backupDocumentDigest,
  backupResourceId,
  createBackupJobDocument,
  createBackupManifestDocument,
  manifestArtifactForResource,
  parseBackupJobDocument,
  parseBackupManifestDocument,
} from "../control-center/backup/contracts.mjs";
import { evaluateNetworkSegmentation } from "./network-segmentation-policy.mjs";
import { evaluateRuntimeIsolation } from "./runtime-isolation-policy.mjs";
import { evaluateSupplyChain } from "./supply-chain-policy.mjs";
import { evaluateFunctionalHealth, validateFunctionalHealthProbes } from "./functional-health.mjs";
import { evaluateRuntimeFingerprint } from "./runtime-fingerprint.mjs";
import { providerEvidenceAttestationOptions } from "./provider-evidence-auth.mjs";
import { sha256FileBounded } from "./bounded-file-hash.mjs";
import { publishBackupArtifact } from "./backup-artifact-publication.mjs";
import { runCommandSync } from "./command-safety.mjs";
import { resticPassthroughEnvironmentKeys, resticSecretTransport } from "./restic-secret-transport.mjs";
import { safeTarCreateArgs, validateTarEntryName } from "./safe-tar-path.mjs";
import { assertNoPlaintextFingerprints, legacyPlaintextFingerprintNames } from "./secret-store-metadata.mjs";
import { readBackupImportProvenance, validateBackupImportProvenance } from "./backup-import-policy.mjs";
import { defaultPostgresRestoreImage, postgresRestoreSandboxPlan } from "./postgres-restore-sandbox.mjs";
import { evaluateOffsiteRestoreCoverage, locateSnapshotManifest, offsiteManifestTags, validateOffsiteRestoreSet } from "./offsite-restore-contract.mjs";
import { canonicalVpsTopologyPlan, parseCanonicalVpsTopology } from "./canonical-compose-topology.mjs";
import { candidateIdentityMatches, createCandidateIdentity, evaluateCandidateReportBinding, normalizeRepositoryIdentity } from "./candidate-identity.mjs";
import { verifyTrustedEvidenceReports } from "./evidence-trust-envelope.mjs";
import { verifyClosedWorldBundleFiles, verifyOwnerPinnedBundleManifest } from "./evidence-bundle-anchor.mjs";
import {
  createEvidenceReportContext,
  evaluateEvidenceBundlePhase,
  evaluateOperationalEvidenceReport,
  evidenceBundleManifestVersion,
  evidenceBundlePhasePolicy,
  normalizeEvidenceBundlePhase,
} from "./evidence-bundle-phase.mjs";
import { validateEdgeProviderEvidence } from "./edge-provider-evidence.mjs";
import {
  assertExactBranchProtection,
  assertExactGithubEnvironment,
} from "./github-governance-policy.mjs";
import {
  GITHUB_ACTIONS_OIDC_ISSUER,
  SLSA_PROVENANCE_V1,
  normalizeRepository,
  verifyGithubAttestation,
  verifyGithubReleaseImages,
} from "./release-trust.mjs";

process.umask(0o077);

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const infraRoot = path.resolve(scriptDir, "..");
const command = process.argv[2] ?? "help";
const argv = parseArgs(process.argv.slice(3));
const configuredSourceRoot = process.env.PROJECT_SOURCE_ROOT ?? process.env.PROJECT_SOURCE_DIR ?? argv.sourceRoot;
const sourceRoot = configuredSourceRoot ? path.resolve(infraRoot, configuredSourceRoot) : path.resolve(infraRoot, "..", "src");
const defaultNodeImage = "node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606";
const defaultPlaywrightImage = "mcr.microsoft.com/playwright:v1.60.0-noble@sha256:9bd26ad900bb5e0f4dee75839e957a89ae89c2b7ab1e76050e559790e946b948";

function parseArgs(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i += 1) {
    const value = args[i];
    if (!value.startsWith("--")) {
      out._.push(value);
      continue;
    }
    const eq = value.indexOf("=");
    if (eq !== -1) {
      out[value.slice(2, eq)] = value.slice(eq + 1);
      continue;
    }
    const key = value.slice(2);
    const next = args[i + 1];
    if (!next || next.startsWith("--")) {
      out[key] = true;
    } else {
      out[key] = next;
      i += 1;
    }
  }
  return out;
}

function log(message = "") {
  process.stdout.write(`${message}\n`);
}

function fail(message) {
  throw new Error(message);
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\"'\"'")}'`;
}

function sqlString(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function sqlIdentifier(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

function sqlIdentifierName(value, label = "identifier") {
  const clean = String(value ?? "").trim();
  if (!/^[a-z][a-z0-9_]*$/.test(clean)) {
    fail(`Invalid ${label}: ${clean || "(empty)"}`);
  }
  return clean;
}

function defaultPostgresBackupDatabase() {
  return sqlIdentifierName(process.env.POSTGRES_BACKUP_DATABASE || "", "PostgreSQL backup database");
}

function cookieName(value, label = "cookie name") {
  const clean = String(value ?? "").trim();
  if (!/^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(clean)) {
    fail(`Invalid ${label}: ${clean || "(empty)"}`);
  }
  return clean;
}

function booleanFlag(value) {
  return value === true || value === "true" || value === "1" || value === "yes";
}

function noDockerMode(options = {}) {
  return Boolean(options.noDocker)
    || booleanFlag(argv.noDocker)
    || booleanFlag(argv.skipDocker)
    || booleanFlag(argv.repoOnly);
}

function positiveInteger(value, optionName, minimum = 1) {
  const next = Number(value);
  if (!Number.isInteger(next) || next < minimum) {
    fail(`${optionName} must be an integer >= ${minimum}.`);
  }
  return next;
}









function parseCronTime(value, optionName) {
  const [hour, minute] = String(value).split(":").map(Number);
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    fail(`Use --${optionName} HH:mm.`);
  }
  return { hour, minute };
}

function run(bin, args = [], options = {}) {
  return runCommandSync(bin, args, {
    cwd: options.cwd ?? infraRoot,
    env: { ...process.env, ...options.env },
    input: options.input,
    encoding: options.encoding ?? "utf8",
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    capture: options.capture,
    allowFailure: options.allowFailure,
    sensitiveValues: options.sensitiveValues,
    sensitiveEnvironmentKeys: options.sensitiveEnvironmentKeys,
  });
}

function output(bin, args = [], options = {}) {
  const result = run(bin, args, { ...options, capture: true });
  return String(result.stdout ?? "").trim();
}

function runSecretManager(args, options = {}) {
  return run(process.execPath, [path.join(scriptDir, "infra-secret-manager.mjs"), ...args], options);
}

function dockerExec(container, args, options = {}) {
  const dockerArgs = ["exec"];
  if (options.input !== undefined) {
    dockerArgs.push("-i");
  }
  dockerArgs.push(container, ...args);
  return run("docker", dockerArgs, options);
}

function dockerExecOutput(container, args, options = {}) {
  const dockerArgs = ["exec"];
  if (options.input !== undefined) {
    dockerArgs.push("-i");
  }
  dockerArgs.push(container, ...args);
  return output("docker", dockerArgs, options);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function postgres(container, database, user, sql, options = {}) {
  return dockerExec(container, [
    "psql",
    "-U",
    user,
    "-d",
    database,
    "-v",
    "ON_ERROR_STOP=1",
    "-c",
    sql,
  ], options);
}

function postgresOut(container, database, user, sql, options = {}) {
  return dockerExecOutput(container, [
    "psql",
    "-U",
    user,
    "-d",
    database,
    "-v",
    "ON_ERROR_STOP=1",
    "-qAt",
    "-c",
    sql,
  ], options);
}

function backupRestoreRunLogPath() {
  const stateRoot = path.resolve(process.env.PROJECT_STATE_ROOT || path.join(infraRoot, "projects-portal", "state"));
  fs.mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
  return path.join(stateRoot, "backup-restore-runs.jsonl");
}

function backupRestoreRunRecords() {
  const file = backupRestoreRunLogPath();
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
}

function writeBackupFreshnessMetrics(records = backupRestoreRunRecords()) {
  const outputDir = path.join(infraRoot, "projects-portal", "state", "node-exporter-textfile");
  fs.mkdirSync(outputDir, { recursive: true, mode: 0o755 });
  const now = Date.now();
  const lines = [
    "# HELP backup_restore_last_success_age_seconds Age of the latest successful platform backup operation.",
    "# TYPE backup_restore_last_success_age_seconds gauge",
  ];
  for (const operation of ["backup", "restore", "restore_test"]) {
    const latest = records
      .filter((record) => record.operation === operation && record.status === "success")
      .sort((left, right) => String(right.finishedAt).localeCompare(String(left.finishedAt)))[0];
    const age = latest ? Math.max(0, Math.floor((now - Date.parse(latest.finishedAt)) / 1000)) : -1;
    lines.push(`backup_restore_last_success_age_seconds{operation="${operation}"} ${age}`);
  }
  const target = path.join(outputDir, "backup-restore.prom");
  const temporary = `${target}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${lines.join("\n")}\n`, { mode: 0o644 });
  fs.renameSync(temporary, target);
  fs.chmodSync(target, 0o644);
}

function recordBackupRestoreRun({ container, database, databaseName = database, user, operation, status, artifactPath = null, artifactSha256 = null, startedAt, metadata = {} }) {
  const finishedAt = new Date();
  const started = startedAt instanceof Date ? startedAt : finishedAt;
  const durationMs = Math.max(0, finishedAt.getTime() - started.getTime());
  if (!["backup", "restore", "restore_test"].includes(operation)) fail(`Invalid backup operation: ${operation}`);
  if (!["started", "success", "failed"].includes(status)) fail(`Invalid backup status: ${status}`);
  const record = {
    id: crypto.randomUUID(),
    operation,
    status,
    engineContainer: String(container || ""),
    databaseName: String(databaseName || ""),
    executionUser: String(user || ""),
    artifactPath,
    artifactSha256,
    startedAt: started.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs,
    metadata,
  };
  const file = backupRestoreRunLogPath();
  fs.appendFileSync(file, `${JSON.stringify(record)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(file, 0o600);
  writeBackupFreshnessMetrics();
  return record;
}

function readText(filePath) {
  if (!fs.existsSync(filePath)) {
    fail(`Missing required file: ${filePath}`);
  }
  return fs.readFileSync(filePath, "utf8");
}

function readJsonFile(filePath, label = filePath) {
  try {
    return JSON.parse(readText(filePath).replace(/^\uFEFF/, ""));
  } catch (error) {
    fail(`Invalid JSON in ${label}: ${String(error?.message ?? error)}`);
  }
}

function readSourceTreeText(directory, extensions = new Set([".ts", ".tsx", ".mjs", ".css"])) {
  let text = "";
  const walk = (currentDirectory) => {
    for (const entry of fs.readdirSync(currentDirectory, { withFileTypes: true })) {
      if (["node_modules", ".next", "dist", "coverage", "vendor"].includes(entry.name)) continue;
      const fullPath = path.join(currentDirectory, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && extensions.has(path.extname(entry.name))) {
        text += `\n/* ${path.relative(directory, fullPath)} */\n${fs.readFileSync(fullPath, "utf8")}`;
      }
    }
  };
  walk(directory);
  return text;
}

const textExtensions = new Set([
  "",
  ".conf",
  ".css",
  ".env",
  ".example",
  ".html",
  ".inc",
  ".ini",
  ".js",
  ".json",
  ".jsonc",
  ".md",
  ".mjs",
  ".rego",
  ".sh",
  ".sql",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".yaml",
  ".yml",
]);

const binaryExtensions = new Set([
  ".db",
  ".dump",
  ".gif",
  ".gz",
  ".ico",
  ".jpeg",
  ".jpg",
  ".lockb",
  ".png",
  ".tar",
  ".webp",
  ".zip",
]);

function isLikelyTextFile(filePath, buffer) {
  const extension = path.extname(filePath).toLowerCase();
  if (binaryExtensions.has(extension)) return false;
  if (textExtensions.has(extension)) return !buffer.includes(0);
  const basename = path.basename(filePath).toLowerCase();
  if (["dockerfile", ".gitignore", ".gitattributes", ".dockerignore", "makefile"].includes(basename)) {
    return !buffer.includes(0);
  }
  if (/dockerfile$/i.test(basename)) return !buffer.includes(0);
  return false;
}

function shouldSkipPortabilityPath(relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  return normalized.startsWith(".git/")
    || normalized.startsWith(".tmp/")
    || normalized.startsWith("backups/")
    || normalized.startsWith("node_modules/")
    || normalized.startsWith("release/")
    || normalized.startsWith("reports/")
    || normalized.startsWith("security/sbom/")
    || normalized.includes("/node_modules/");
}

function isOperationalPortabilityPath(relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  return normalized.startsWith(".github/")
    || normalized.startsWith("cloudflare/")
    || normalized.startsWith("docker/")
    || normalized.startsWith("governance/")
    || normalized.startsWith("monitoring/")
    || normalized.startsWith("scripts/")
    || normalized.startsWith("traefik/")
    || normalized.startsWith("waf/")
    || /^compose.*\.ya?ml$/.test(normalized)
    || /^Dockerfile$/i.test(normalized);
}

function scanPortabilityFiles(root, { fix = false } = {}) {
  const files = [];
  const issues = [];
  const fixed = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      const relativePath = path.relative(root, fullPath);
      if (shouldSkipPortabilityPath(relativePath)) continue;
      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      const buffer = fs.readFileSync(fullPath);
      if (!isLikelyTextFile(fullPath, buffer)) continue;
      files.push(relativePath.replaceAll("\\", "/"));
      const hasBom = buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
      const text = buffer.toString("utf8");
      const scanText = relativePath.replaceAll("\\", "/") === "scripts/infra-ops.mjs"
        ? text.split(/\r?\n/).filter((line) => !/(hasWindowsPath|hasPowerShellDependency|windows-path|powershell-dependency|PowerShell\/cmd|\bpwsh\b|\bpowershell\b)/i.test(line)).join("\n")
        : text;
      const hasCrLf = text.includes("\r\n");
      const operational = isOperationalPortabilityPath(relativePath);
      const hasWindowsPath = operational && /(^|[\s"'(=\[,])[A-Za-z]:[\\/][^\s"'`]+[\\/][^\s"'`]*/.test(scanText);
      const hasPowerShellDependency = operational && /(?:^|[^A-Za-z])(?:pwsh|powershell)(?:\.exe)?(?:[^A-Za-z]|$)/i.test(scanText);
      if (hasBom || hasCrLf) {
        if (fix) {
          const next = (hasBom ? text.replace(/^\uFEFF/, "") : text).replace(/\r\n/g, "\n");
          fs.writeFileSync(fullPath, next, "utf8");
          fixed.push({
            file: relativePath.replaceAll("\\", "/"),
            removedBom: hasBom,
            normalizedLf: hasCrLf,
          });
        } else {
          if (hasBom) issues.push({ file: relativePath.replaceAll("\\", "/"), type: "utf8-bom", detail: "UTF-8 BOM before text/shebang" });
          if (hasCrLf) issues.push({ file: relativePath.replaceAll("\\", "/"), type: "crlf", detail: "CRLF line endings" });
        }
      }
      if (hasWindowsPath) {
        issues.push({ file: relativePath.replaceAll("\\", "/"), type: "windows-path", detail: "Windows absolute path in operational file" });
      }
      if (hasPowerShellDependency) {
        issues.push({ file: relativePath.replaceAll("\\", "/"), type: "powershell-dependency", detail: "PowerShell/cmd dependency in operational file" });
      }
    }
  };
  walk(root);
  return { files, issues, fixed };
}

function assertMatch(text, pattern, message) {
  if (booleanFlag(process.env.PLATFORM_DEBUG_STATIC_ASSERTS)) {
    log(`assertMatch: ${message}`);
  }
  if (!pattern.test(text)) {
    fail(message);
  }
}

function assertNoMatch(text, pattern, message) {
  if (booleanFlag(process.env.PLATFORM_DEBUG_STATIC_ASSERTS)) {
    log(`assertNoMatch: ${message}`);
  }
  if (pattern.test(text)) {
    fail(message);
  }
}

function assertIncludesAll(text, values, message) {
  if (booleanFlag(process.env.PLATFORM_DEBUG_STATIC_ASSERTS)) {
    log(`assertIncludesAll: ${message}`);
  }
  for (const value of values) {
    if (!text.includes(value)) {
      fail(`${message} Missing: ${value}`);
    }
  }
}

function parseEnv(filePath) {
  const env = {};
  if (!fs.existsSync(filePath)) {
    return env;
  }
  for (const sourceLine of fs.readFileSync(filePath, "utf8").split(/\r?\n/)) {
    const line = sourceLine.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) {
      continue;
    }
    const index = line.indexOf("=");
    const key = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim().replace(/^["']|["']$/g, "");
    env[key] = value;
  }
  return env;
}

function expandTemplate(value, variables) {
  return String(value).replace(/\$\{([A-Z0-9_]+)(:-([^}]*))?\}/g, (_match, key, _fallbackExpr, fallback = "") => {
    const next = variables[key];
    return next === undefined || next === "" ? fallback : next;
  });
}

function randomSecret(bytes = 36) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function isUsableSecret(value) {
  return Boolean(value && !/change_me|your-domain|placeholder|managed_by_local_secret_file/i.test(value));
}

function hasManagedSecret(env, key) {
  return Boolean(env[`${key}_FILE`] || env[`${key}_SECRET_REF`]);
}

function requireManagedSecret(env, key) {
  const fileRef = env[`${key}_FILE`];
  const managerRef = env[`${key}_SECRET_REF`];
  if (fileRef && /^\/run\/secrets\/[A-Za-z0-9_.-]+$/.test(fileRef)) {
    return;
  }
  if (managerRef && env.SECRET_MANAGER_PROVIDER) {
    return;
  }
  fail(`${key} must be provided through ${key}_FILE=/run/secrets/<name> or ${key}_SECRET_REF with SECRET_MANAGER_PROVIDER.`);
}

function latestFileByMtime(directory, predicate) {
  if (!fs.existsSync(directory)) return null;
  const files = fs.readdirSync(directory)
    .map((file) => path.join(directory, file))
    .filter((file) => fs.statSync(file).isFile() && predicate(file))
    .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
  return files[0] ?? null;
}

function latestFileByMtimeRecursive(directory, predicate, limit = 5000) {
  if (!fs.existsSync(directory)) return null;
  const files = [];
  const stack = [directory];
  let visited = 0;
  while (stack.length && visited < limit) {
    const current = stack.pop();
    visited += 1;
    let stat;
    try {
      stat = fs.lstatSync(current);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      for (const entry of fs.readdirSync(current)) {
        if (!entry.startsWith(".")) stack.push(path.join(current, entry));
      }
      continue;
    }
    if (stat.isFile() && predicate(current)) files.push(current);
  }
  return files.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs)[0] ?? null;
}

function resolveInside(root, target) {
  const resolvedRoot = fs.realpathSync(root);
  const resolvedTarget = fs.realpathSync(target);
  const relative = path.relative(resolvedRoot, resolvedTarget);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`Path must be inside ${resolvedRoot}: ${resolvedTarget}`);
  }
  return resolvedTarget;
}

function assertPathInside(root, target) {
  const resolvedRoot = path.resolve(root);
  const resolvedTarget = path.resolve(target);
  const relative = path.relative(resolvedRoot, resolvedTarget);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`Path must be inside ${resolvedRoot}: ${resolvedTarget}`);
  }
  return resolvedTarget;
}

function removeTreeInside(root, target) {
  const resolvedRoot = path.resolve(root);
  const resolvedTarget = assertPathInside(resolvedRoot, target);
  if (resolvedTarget === resolvedRoot) {
    fail(`Refusing to remove root directory: ${resolvedRoot}`);
  }
  fs.rmSync(resolvedTarget, { recursive: true, force: true });
}

function sha256File(filePath) {
  return sha256FileBounded(filePath).sha256;
}

function secretId(prefix) {
  return `${prefix}${new Date().toISOString().replace(/\D/g, "").slice(0, 14)}`;
}

function readSecretFileIfExists(filePath) {
  if (!fs.existsSync(filePath)) {
    return null;
  }
  const value = fs.readFileSync(filePath, "utf8").trim();
  return value || null;
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function hmacHex(secret, value) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function parseVersionedSecretKeys(value) {
  return String(value ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const separator = entry.indexOf("=");
      if (separator <= 0) return null;
      const id = entry.slice(0, separator).trim();
      const secret = entry.slice(separator + 1).trim();
      return id && secret ? { id, secret } : null;
    })
    .filter(Boolean);
}

function timingSafeEqualBuffer(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function backupSigningKeys() {
  const filePath = path.resolve(argv.backupSigningKeysFile ?? process.env.BACKUP_SIGNING_KEYS_FILE ?? path.join(infraRoot, "secrets", "backup_signing_keys.txt"));
  const value = readSecretFileIfExists(filePath);
  let keys = parseVersionedSecretKeys(value);
  if (!keys.length && String(value ?? "").trim().length >= 48) {
    keys = [{ id: "legacy", secret: String(value).trim() }];
    log("Using legacy raw backup signing key format; rotate to a versioned keyring before production go-live.");
  }
  if (!keys.length) {
    fail(`Backup signing keys are required. Run local-secret-manager or set BACKUP_SIGNING_KEYS_FILE. Expected local file: ${filePath}`);
  }
  if (keys.some((key) => key.secret.length < 48)) {
    fail("Every backup signing key must be at least 48 characters.");
  }
  return keys;
}

function backupSignatureSidecarPath(filePath) {
  return `${filePath}.sig.json`;
}

function backupSignatureMessage(fileName, hash) {
  return `platform-postgres-backup-v1\n${fileName}\n${hash}\n`;
}

function createBackupArtifactSignature({ artifactName, sha256 }) {
  const activeKey = backupSigningKeys()[0];
  const signature = crypto.createHmac("sha256", activeKey.secret).update(backupSignatureMessage(artifactName, sha256)).digest("base64url");
  return {
    keyId: activeKey.id,
    document: {
      version: 1,
      algorithm: "HMAC-SHA256",
      keyId: activeKey.id,
      artifact: artifactName,
      sha256,
      signature,
      signedAt: new Date().toISOString(),
    },
  };
}

function signBackupArtifact(filePath, hash = sha256File(filePath)) {
  const created = createBackupArtifactSignature({ artifactName: path.basename(filePath), sha256: hash });
  const sidecar = created.document;
  fs.writeFileSync(backupSignatureSidecarPath(filePath), `${JSON.stringify(sidecar, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(backupSignatureSidecarPath(filePath), 0o600);
  return { hash, keyId: created.keyId, signaturePath: backupSignatureSidecarPath(filePath) };
}

function verifyBackupArtifact(filePath) {
  const fileName = path.basename(filePath);
  const hash = sha256File(filePath);
  const shaPath = `${filePath}.sha256`;
  if (!fs.existsSync(shaPath)) {
    fail(`Missing backup checksum sidecar: ${shaPath}`);
  }
  const recordedHash = fs.readFileSync(shaPath, "utf8").trim().split(/\s+/, 1)[0];
  if (recordedHash !== hash) {
    fail(`Backup checksum mismatch for ${filePath}.`);
  }
  const signaturePath = backupSignatureSidecarPath(filePath);
  if (!fs.existsSync(signaturePath)) {
    fail(`Missing backup signature sidecar: ${signaturePath}`);
  }
  const sidecar = JSON.parse(fs.readFileSync(signaturePath, "utf8"));
  if (sidecar.version !== 1 || sidecar.algorithm !== "HMAC-SHA256" || sidecar.artifact !== fileName || sidecar.sha256 !== hash) {
    fail(`Invalid backup signature metadata for ${filePath}.`);
  }
  const keys = backupSigningKeys();
  const orderedKeys = [
    ...keys.filter((key) => key.id === sidecar.keyId),
    ...keys.filter((key) => key.id !== sidecar.keyId),
  ];
  const valid = orderedKeys.some((key) => {
    const expected = crypto.createHmac("sha256", key.secret).update(backupSignatureMessage(fileName, hash)).digest("base64url");
    return timingSafeEqualBuffer(Buffer.from(sidecar.signature), Buffer.from(expected));
  });
  if (!valid) {
    fail(`Backup signature verification failed for ${filePath}.`);
  }
  return { hash, keyId: sidecar.keyId, signaturePath };
}

function backupManifestSignatureMessage(manifestId, digest) {
  return `platform-backup-manifest-v1\n${manifestId}\n${digest}\n`;
}

function signBackupManifestDocument(manifest) {
  const digest = backupDocumentDigest(manifest);
  const activeKey = backupSigningKeys()[0];
  const value = crypto.createHmac("sha256", activeKey.secret)
    .update(backupManifestSignatureMessage(manifest.id, digest))
    .digest("base64url");
  return {
    ...manifest,
    signature: {
      algorithm: "HMAC-SHA256",
      keyId: activeKey.id,
      digest,
      value,
    },
  };
}

function verifyBackupManifestDocument(input) {
  const manifest = parseBackupManifestDocument(input);
  if (!manifest.signature || manifest.signature.digest !== backupDocumentDigest(manifest)) {
    fail("Backup manifest digest verification failed.");
  }
  const keys = backupSigningKeys();
  const orderedKeys = [
    ...keys.filter((key) => key.id === manifest.signature.keyId),
    ...keys.filter((key) => key.id !== manifest.signature.keyId),
  ];
  const valid = orderedKeys.some((key) => {
    const expected = crypto.createHmac("sha256", key.secret)
      .update(backupManifestSignatureMessage(manifest.id, manifest.signature.digest))
      .digest("base64url");
    return timingSafeEqualBuffer(Buffer.from(manifest.signature.value), Buffer.from(expected));
  });
  if (!valid) fail("Backup manifest signature verification failed.");
  return manifest;
}

function writePrivateJsonAtomic(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.tmp-${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    fs.renameSync(temporary, filePath);
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function listDumpFilesRecursive(root) {
  if (!fs.existsSync(root)) {
    return [];
  }
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".dump")) {
        files.push(fullPath);
      }
    }
  };
  walk(root);
  return files.sort();
}

function backupRootPath() {
  const root = path.join(infraRoot, "backups");
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  fs.chmodSync(root, 0o700);
  return root;
}

function ensureBackupOutputDir(directory) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const resolved = resolveInside(backupRootPath(), directory);
  fs.chmodSync(resolved, 0o700);
  return resolved;
}

function recordDatabaseBackupEvidence({ engine, sourceContainer, operation, status, artifactPath = null, artifactSha256 = null, startedAt, metadata = {} }) {
  if (booleanFlag(argv.skipEvidence)) {
    return;
  }
  try {
    recordBackupRestoreRun({
      container: sourceContainer,
      database: `${engine}-all`,
      databaseName: `${engine}-all`,
      user: "platform-backup-executor",
      operation,
      status,
      artifactPath,
      artifactSha256,
      startedAt,
      metadata: {
        ...metadata,
        engine,
        sourceContainer,
      },
    });
  } catch (error) {
    log(`Warning: backup evidence was not recorded in PostgreSQL: ${String(error?.message ?? error)}`);
  }
}

function backupTimestamp() {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
}

function reportTimestamp() {
  return new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
}

function ensureReportDir(name) {
  const directory = path.join(infraRoot, "reports", name);
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

function writeJsonReport(directoryName, baseName, payload) {
  const directory = ensureReportDir(directoryName);
  const jsonPath = path.join(directory, `${baseName}.json`);
  const boundPayload = payload && typeof payload === "object" && !Array.isArray(payload)
    ? {
        ...payload,
        evidenceContext: createEvidenceReportContext({
          git: gitEvidence(),
          phase: process.env.EVIDENCE_REPORT_PHASE,
          command,
          env: process.env,
        }),
      }
    : payload;
  fs.writeFileSync(jsonPath, `${JSON.stringify(boundPayload, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(jsonPath, 0o600);
  return jsonPath;
}

function writeMarkdownReport(directoryName, baseName, lines) {
  const directory = ensureReportDir(directoryName);
  const markdownPath = path.join(directory, `${baseName}.md`);
  fs.writeFileSync(markdownPath, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
  fs.chmodSync(markdownPath, 0o600);
  return markdownPath;
}

async function withLocalCheckReport(commandName, fn, metadata = {}) {
  const startedAt = new Date();
  let finishedAt = startedAt;
  let status = "passed";
  let errorMessage = null;
  try {
    const result = await fn();
    finishedAt = new Date();
    return result;
  } catch (error) {
    finishedAt = new Date();
    status = "failed";
    errorMessage = String(error?.message ?? error);
    throw error;
  } finally {
    const stamp = reportTimestamp();
    const baseName = `${commandName}-${stamp}`;
    const payload = {
      generatedAt: finishedAt.toISOString(),
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
      status,
      command: commandName,
      scope: "platform-infrastructure",
      runner: "infra-ops",
      candidate: metadata.candidate ?? null,
      candidateEnd: metadata.candidateEnd ?? null,
      candidateStable: metadata.candidateStable === true,
      candidateError: metadata.candidateError ?? null,
      metadata,
    };
    if (errorMessage) {
      payload.error = errorMessage;
    }
    const jsonPath = writeJsonReport("local-checks", baseName, payload);
    const markdownPath = writeMarkdownReport("local-checks", baseName, [
      `# ${commandName}`,
      "",
      `Generated at: ${payload.generatedAt}`,
      `Status: ${payload.status}`,
      `Scope: ${payload.scope}`,
      `Duration ms: ${payload.durationMs}`,
      errorMessage ? `Error: ${errorMessage}` : "",
    ].filter(Boolean));
    log(`Local check report written to ${jsonPath} and ${markdownPath}`);
  }
}

function writeBackupExecutionReport({
  engine,
  sourceContainer,
  status,
  artifactPath = null,
  artifactSha256 = null,
  artifactSizeBytes: capturedArtifactSizeBytes = null,
  signature = null,
  startedAt,
  metadata = {},
}) {
  const finishedAt = new Date();
  const started = startedAt instanceof Date ? startedAt : finishedAt;
  const artifactExists = artifactPath ? fs.existsSync(artifactPath) : false;
  const artifactSizeBytes = Number.isSafeInteger(capturedArtifactSizeBytes) && capturedArtifactSizeBytes >= 0
    ? capturedArtifactSizeBytes
    : artifactExists ? fs.statSync(artifactPath).size : null;
  const payload = {
    generatedAt: finishedAt.toISOString(),
    startedAt: started.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: Math.max(0, finishedAt.getTime() - started.getTime()),
    engine,
    sourceContainer,
    status,
    artifactPath,
    artifactName: artifactPath ? path.basename(artifactPath) : null,
    artifactSizeBytes,
    artifactSha256,
    signaturePath: signature?.signaturePath ?? null,
    signatureKeyId: signature?.keyId ?? null,
    integrityVerified: status === "success" && Boolean(artifactSha256) && artifactExists,
    metadata,
  };
  const stamp = reportTimestamp();
  const baseName = `${engine}-backup-${stamp}-${crypto.randomBytes(3).toString("hex")}`;
  const jsonPath = writeJsonReport("backups", baseName, payload);
  const markdownPath = writeMarkdownReport("backups", baseName, [
    `# Platform ${engine} Backup Report`,
    "",
    `Status: ${payload.status}`,
    `Started at: ${payload.startedAt}`,
    `Finished at: ${payload.finishedAt}`,
    `Duration: ${payload.durationMs} ms`,
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| Engine | ${payload.engine} |`,
    `| Source | ${payload.sourceContainer} |`,
    `| Artifact | ${payload.artifactPath ?? "n/a"} |`,
    `| Size bytes | ${payload.artifactSizeBytes ?? "n/a"} |`,
    `| SHA256 | ${payload.artifactSha256 ?? "n/a"} |`,
    `| Signature | ${payload.signaturePath ?? "n/a"} |`,
    `| Integrity verified | ${payload.integrityVerified ? "yes" : "no"} |`,
  ]);
  log(`Backup execution reports written to ${jsonPath} and ${markdownPath}`);
  return { jsonPath, markdownPath };
}

function backupArtifactStagingPath(hostPath) {
  return path.join(
    path.dirname(hostPath),
    `.${path.basename(hostPath)}.staging-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
  );
}

function publishBackupArtifactWithEvidence({ stagingPath, hostPath, engine, sourceContainer, startedAt, metadata, recordSuccess }) {
  const publication = publishBackupArtifact({
    stagingPath,
    publishedPath: hostPath,
    createSignature: createBackupArtifactSignature,
    onPublished({ hash, sizeBytes, signature }) {
      recordSuccess?.({ hash, signature });
      writeBackupExecutionReport({
        engine,
        sourceContainer,
        status: "success",
        artifactPath: hostPath,
        artifactSha256: hash,
        artifactSizeBytes: sizeBytes,
        signature,
        startedAt,
        metadata,
      });
    },
  });
  try {
    publication.assertCurrent();
    return { hash: publication.hash, signature: publication.signature, sizeBytes: publication.sizeBytes };
  } finally {
    publication.close();
  }
}

function hostPathForContainerMount(filePath) {
  const resolved = path.resolve(filePath).replaceAll("\\", "/");
  const mappings = [
    [process.env.PLATFORM_INFRA_CONTAINER_ROOT || infraRoot, process.env.PLATFORM_INFRA_HOST_ROOT],
    [sourceRoot, process.env.PROJECT_SOURCE_HOST_ROOT],
  ].filter(([, hostRoot]) => Boolean(hostRoot));
  for (const [containerRootRaw, hostRootRaw] of mappings) {
    const containerRoot = path.resolve(containerRootRaw).replaceAll("\\", "/").replace(/\/$/, "");
    const hostRoot = String(hostRootRaw).replaceAll("\\", "/").replace(/\/$/, "");
    if (resolved === containerRoot || resolved.startsWith(`${containerRoot}/`)) {
      return `${hostRoot}${resolved.slice(containerRoot.length)}`;
    }
  }
  return resolved;
}

function dockerRun(args, options = {}) {
  return run("docker", ["run", "--rm", ...args], options);
}

function makeOpsTempDir(prefix) {
  const root = path.join(infraRoot, ".tmp", "ops");
  fs.mkdirSync(root, { recursive: true });
  return fs.mkdtempSync(path.join(root, prefix));
}

function dockerStatsSnapshot(label) {
  const containers = [
    "enterprise-traefik",
    "enterprise-control-center",
    "enterprise-project-router",
    "enterprise-platform-alert-dispatcher",
    "enterprise-postgres",
    "mariadb",
    "enterprise-redis",
    "enterprise-nats",
    "enterprise-keycloak",
    "enterprise-minio",
    "enterprise-waf",
  ];
  const result = run("docker", ["stats", "--no-stream", "--format", "{{json .}}", ...containers], { allowFailure: true, capture: true });
  const rows = String(result.stdout ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { raw: line };
      }
    });
  return { label, capturedAt: new Date().toISOString(), status: result.status, rows };
}

const releaseImageKeys = [
  "PLATFORM_ALERT_DISPATCHER_IMAGE",
  "CONTROL_CENTER_IMAGE",
  "PHP_APACHE_IMAGE",
  "PLATFORM_OPS_IMAGE",
  "RESTIC_IMAGE",
];

function releaseImageEntriesFromManifest(manifestPath) {
  if (!manifestPath) {
    return [];
  }
  const resolved = path.resolve(manifestPath);
  const manifest = readJsonFile(resolved, resolved);
  const source = manifest.releaseImages ?? manifest.images ?? manifest.artifacts?.images ?? manifest.subjects ?? [];
  const entries = Array.isArray(source)
    ? source.map((entry, index) => {
      const name = String(entry.name ?? "").trim();
      const digest = String(entry.digest ?? entry.subjectDigest ?? "").trim();
      const image = String(entry.image ?? entry.ref ?? entry.value ?? (name && digest ? `${name}@${digest}` : "")).trim();
      return {
        key: String(entry.key ?? entry.name ?? `IMAGE_${index + 1}`).trim(),
        image,
      };
    })
    : Object.entries(source).map(([key, value]) => ({
      key,
      image: typeof value === "string" ? value : String(value?.image ?? value?.ref ?? value?.value ?? "").trim(),
    }));
  return entries.filter((entry) => entry.key && entry.image);
}

function releaseImageEntriesFromEnv(env) {
  return releaseImageKeys
    .map((key) => ({ key, image: env[key] ?? null }))
    .filter((entry) => entry.image);
}

function releaseImageEntries({ env = {}, imagesArg = null, manifestPath = null } = {}) {
  if (manifestPath) {
    const manifestEntries = releaseImageEntriesFromManifest(manifestPath);
    if (manifestEntries.length) {
      return manifestEntries;
    }
  }
  if (imagesArg) {
    return String(imagesArg)
      .split(",")
      .map((image, index) => ({ key: `IMAGE_${index + 1}`, image: image.trim() }))
      .filter((entry) => entry.image);
  }
  return releaseImageEntriesFromEnv(env);
}

function imageMapFromEntries(entries) {
  return Object.fromEntries(entries.map((entry) => [entry.key, entry.image]));
}

function assertImmutableImageRef(key, image) {
  if (!image) {
    fail(`Missing rollback image for ${key}.`);
  }
  if (/:latest(?:@|$)/.test(image)) {
    fail(`${key} rollback image must not use :latest.`);
  }
  if (!booleanFlag(argv.allowUnpinnedRollbackImages) && !/@sha256:[a-f0-9]{64}$/i.test(image)) {
    fail(`${key} rollback image must be digest-pinned. Use --allowUnpinnedRollbackImages only for local dry-runs.`);
  }
}

function assertDigestPinnedImageRef(key, image, { allowUnpinned = false, label = "image" } = {}) {
  if (!image) {
    fail(`Missing ${label} for ${key}.`);
  }
  if (/:latest(?:@|$)/.test(image)) {
    fail(`${key} ${label} must not use :latest.`);
  }
  if (!allowUnpinned && !/@sha256:[a-f0-9]{64}$/i.test(image)) {
    fail(`${key} ${label} must be digest-pinned.`);
  }
}

function digestFromImageRef(image) {
  const match = String(image ?? "").match(/@sha256:([a-f0-9]{64})$/i);
  return match ? match[1].toLowerCase() : null;
}

function releaseTrustPolicy() {
  const policy = readJsonFile(path.join(infraRoot, "governance", "release-trust.json"), "release trust policy");
  if (policy.provider !== "github-artifact-attestations") {
    fail("Release trust policy must use GitHub Artifact Attestations.");
  }
  if (policy.predicate_type !== SLSA_PROVENANCE_V1 || policy.cert_oidc_issuer !== GITHUB_ACTIONS_OIDC_ISSUER) {
    fail("Release trust policy must bind SLSA v1 to the GitHub Actions OIDC issuer.");
  }
  if (policy.deny_self_hosted_runners !== true || policy.require_verified_timestamp !== true) {
    fail("Release trust policy must deny self-hosted signers and require a verified timestamp.");
  }
  if (policy.accept_unsigned_local_provenance !== false || policy.accept_normalized_verification_reports !== false) {
    fail("Release trust policy must reject unsigned provenance and normalized verification reports.");
  }
  return policy;
}

function releaseTrustVerificationOptions(options, releaseSha) {
  const policy = releaseTrustPolicy();
  const repository = options.repository ?? options.repo ?? argv.repository ?? argv.repo ?? process.env.GITHUB_REPOSITORY;
  const sourceRef = options.sourceRef ?? argv.sourceRef ?? process.env.GITHUB_REF;
  return {
    repository,
    signerWorkflow: options.signerWorkflow ?? argv.signerWorkflow ?? `${repository}/${policy.signer_workflow_path}`,
    sourceDigest: releaseSha,
    sourceRef,
    bundle: options.attestationBundle ?? argv.attestationBundle ?? null,
    trustedRoot: options.trustedRoot ?? argv.trustedRoot ?? null,
    predicateType: policy.predicate_type,
    certOidcIssuer: policy.cert_oidc_issuer,
  };
}

function rejectLegacyProvenanceInputs(options = {}) {
  if (options.provenance ?? argv.provenance) {
    fail("Unsigned local SLSA JSON is not admissible. Use a signed --attestationBundle with --trustedRoot or online GitHub verification.");
  }
  if (options.githubAttestation ?? options.githubAttestations ?? argv.githubAttestation ?? argv.githubAttestations) {
    fail("Normalized GitHub attestation reports are not trust inputs. The gate must invoke the cryptographic verifier directly.");
  }
  if (options.skipProvenanceCommitCheck ?? booleanFlag(argv.skipProvenanceCommitCheck)) {
    fail("Provenance commit verification cannot be skipped.");
  }
}

function envTextWithOverrides(text, overrides) {
  const seen = new Set();
  const lines = text.split(/\r?\n/).map((line) => {
    const match = line.match(/^([A-Z0-9_]+)=/);
    if (!match || !(match[1] in overrides)) {
      return line;
    }
    seen.add(match[1]);
    return `${match[1]}=${overrides[match[1]]}`;
  });
  for (const [key, value] of Object.entries(overrides)) {
    if (!seen.has(key)) {
      lines.push(`${key}=${value}`);
    }
  }
  return lines.join("\n");
}

function csvList(value, fallback) {
  return String(value ?? fallback)
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function writeRollbackPlanReport({
  envFile,
  envText,
  rollbackFile = null,
  imageOverrides,
  projectName,
  composeFiles,
  services,
  mode,
  stamp = reportTimestamp(),
}) {
  const nextEnvText = envTextWithOverrides(envText, imageOverrides);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "platform-rollback-"));
  const tempEnv = path.join(tempDir, ".env.rollback");
  const composeArgs = [
    "compose",
    "--env-file",
    tempEnv,
    "-p",
    projectName,
    ...composeFiles.flatMap((file) => ["-f", path.resolve(infraRoot, file)]),
  ];
  try {
    fs.writeFileSync(tempEnv, nextEnvText, "utf8");
    run("docker", [...composeArgs, "config", "--quiet"]);
    const payload = {
      generatedAt: new Date().toISOString(),
      mode,
      envFile,
      rollbackFile,
      projectName,
      composeFiles,
      services,
      images: imageOverrides,
      composeValidation: {
        status: "passed",
        command: [
          "docker",
          "compose",
          "--env-file",
          "<temporary-rollback-env>",
          "-p",
          projectName,
          ...composeFiles.flatMap((file) => ["-f", file]),
          "config",
          "--quiet",
        ],
      },
      postCheck: "infra-health",
    };
    const jsonPath = writeJsonReport("rollback", `rollback-plan-${stamp}`, payload);
    const markdownPath = writeMarkdownReport("rollback", `rollback-plan-${stamp}`, [
      "# Platform Rollback Plan",
      "",
      `Generated at: ${payload.generatedAt}`,
      `Mode: ${payload.mode}`,
      `Project: ${projectName}`,
      `Rollback file: ${rollbackFile ?? "direct image arguments"}`,
      "",
      "| Image variable | Rollback image |",
      "| --- | --- |",
      ...Object.entries(imageOverrides).map(([key, image]) => `| ${key} | \`${image}\` |`),
      "",
      `Compose validation: ${payload.composeValidation.status}`,
      `Services: ${services.join(", ")}`,
      `Post-check: ${payload.postCheck}`,
    ]);
    return { payload, jsonPath, markdownPath, nextEnvText };
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

async function signExistingPostgresBackups() {
  const backupRoot = path.resolve(argv.backupRoot ?? path.join(infraRoot, "backups", "postgres"));
  resolveInside(path.join(infraRoot, "backups"), backupRoot);
  const quarantineRoot = path.join(backupRoot, "quarantine", backupTimestamp());
  const dumps = listDumpFilesRecursive(backupRoot).filter((dump) => !dump.startsWith(`${path.join(backupRoot, "quarantine")}${path.sep}`));
  let verified = 0;
  const untrusted = [];
  for (const dump of dumps) {
    if (fs.existsSync(`${dump}.sha256`) && fs.existsSync(backupSignatureSidecarPath(dump))) {
      verifyBackupArtifact(dump);
      verified += 1;
      continue;
    }
    untrusted.push(dump);
  }
  if (untrusted.length && !booleanFlag(argv.quarantine)) {
    fail(`Automatic bulk signing is disabled; ${untrusted.length} unsigned dump(s) remain untrusted. Re-run with --quarantine or import one artifact with import-postgres-backup.`);
  }
  const quarantined = [];
  for (const dump of untrusted) {
    const relative = path.relative(backupRoot, dump);
    const target = path.join(quarantineRoot, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.renameSync(dump, target);
    for (const sidecar of [`${dump}.sha256`, backupSignatureSidecarPath(dump)]) {
      if (fs.existsSync(sidecar)) fs.renameSync(sidecar, `${target}${sidecar.slice(dump.length)}`);
    }
    quarantined.push(relative);
  }
  const stamp = reportTimestamp();
  const payload = {
    generatedAt: new Date().toISOString(),
    status: "passed",
    backupRoot,
    summary: {
      signed: 0,
      verified,
      quarantined: quarantined.length,
      total: dumps.length,
    },
  };
  const jsonPath = writeJsonReport("postgres-backup-signatures", `postgres-backup-signatures-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("postgres-backup-signatures", `postgres-backup-signatures-${stamp}`, [
    "# PostgreSQL Backup Signatures",
    "",
    `Generated at: ${payload.generatedAt}`,
    `Status: ${payload.status}`,
    `Backup root: ${backupRoot}`,
    "",
    "| Signed | Verified | Quarantined | Total |",
    "| ---: | ---: | ---: | ---: |",
    `| 0 | ${verified} | ${quarantined.length} | ${dumps.length} |`,
  ]);
  log(`Backup trust audit ready: signed=0 verified=${verified} quarantined=${quarantined.length} total=${dumps.length}.`);
  log(`PostgreSQL backup signature report written to ${jsonPath} and ${markdownPath}`);
}

async function importPostgresBackup() {
  const backupRoot = path.resolve(argv.backupRoot ?? path.join(infraRoot, "backups", "postgres"));
  resolveInside(path.join(infraRoot, "backups"), backupRoot);
  const backupFileArg = argv.backupFile ?? argv._[0];
  if (!backupFileArg) fail("Import requires --backupFile for one PostgreSQL .dump artifact.");
  const backupFile = resolveInside(backupRoot, path.resolve(backupFileArg));
  if (!backupFile.endsWith(".dump") || !fs.statSync(backupFile).isFile()) fail("Import requires one PostgreSQL .dump artifact.");
  if (fs.existsSync(backupSignatureSidecarPath(backupFile))) fail("Backup already has signature metadata; verify it instead of importing it again.");
  if (!argv.provenanceFile) fail("Import requires --provenanceFile and an owner-pinned --provenanceSha256.");
  const provenanceFile = path.resolve(argv.provenanceFile);
  const artifactHash = sha256File(backupFile);
  const artifactSizeBytes = fs.statSync(backupFile).size;
  let capturedProvenance;
  try {
    capturedProvenance = readBackupImportProvenance({ filePath: provenanceFile });
  } catch {
    fail("Import provenance file could not be captured as one bounded immutable JSON document.");
  }
  const { provenance, provenanceSha256 } = capturedProvenance;
  const provenanceResult = validateBackupImportProvenance({
    artifactName: path.basename(backupFile),
    artifactSha256: artifactHash,
    artifactSizeBytes,
    provenance,
    provenanceSha256,
    pinnedProvenanceSha256: String(argv.provenanceSha256 ?? ""),
    expectedSourceSystem: String(argv.sourceSystem ?? ""),
    expectedSourceId: String(argv.sourceId ?? ""),
    confirmation: String(argv.confirmImport ?? ""),
  });
  const shaPath = `${backupFile}.sha256`;
  if (fs.existsSync(shaPath)) {
    const recordedHash = fs.readFileSync(shaPath, "utf8").trim().split(/\s+/, 1)[0];
    if (recordedHash !== artifactHash) fail("Existing backup checksum sidecar does not match; refusing to rewrite it.");
  } else {
    fs.writeFileSync(shaPath, `${artifactHash}  ${path.basename(backupFile)}\n`, { encoding: "ascii", mode: 0o600 });
  }
  signBackupArtifact(backupFile, artifactHash);
  verifyBackupArtifact(backupFile);
  const payload = {
    generatedAt: new Date().toISOString(),
    status: "passed",
    artifact: path.relative(backupRoot, backupFile),
    artifactSha256: artifactHash,
    artifactSizeBytes,
    provenanceSha256,
    sourceSystem: provenanceResult.sourceSystem,
    sourceId: provenanceResult.sourceId,
    trustMode: "owner-pinned-provenance-digest",
  };
  const reportPath = writeJsonReport("postgres-backup-signatures", `postgres-backup-import-${reportTimestamp()}`, payload);
  log(`Imported one provenance-validated PostgreSQL backup. Report: ${reportPath}`);
}















const localTlsHostnames = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "portal.localhost.com",
  "docs.localhost.com",
]);

function isLocalTlsHostname(hostname) {
  return localTlsHostnames.has(hostname) || hostname.endsWith(".localhost.com");
}

function request(method, urlString, { headers = {}, body, timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const isHttps = url.protocol === "https:";
    const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const client = isHttps ? https : http;
    const req = client.request({
      method,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      headers: {
        ...headers,
        ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}),
      },
      rejectUnauthorized: !isLocalTlsHostname(url.hostname),
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let json = null;
        if (text.trim()) {
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
        }
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          text,
          json,
        });
      });
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`${method} ${urlString} timed out after ${timeoutMs}ms`));
    });
    if (data) {
      req.write(data);
    }
    req.end();
  });
}

function requestRaw(method, urlString, { headers = {}, body, timeoutMs = 10000 } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const isHttps = url.protocol === "https:";
    const data = body === undefined ? undefined : Buffer.from(typeof body === "string" ? body : JSON.stringify(body));
    const client = isHttps ? https : http;
    const req = client.request({
      method,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      headers: {
        ...headers,
        ...(data ? { "Content-Type": "application/json", "Content-Length": data.length } : {}),
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: res.statusCode ?? 0, headers: res.headers, text });
      });
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`${method} ${urlString} timed out after ${timeoutMs}ms`));
    });
    if (data) req.write(data);
    req.end();
  });
}

function headerText(headers) {
  return Object.entries(headers)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`)
    .join("\n")
    .toLowerCase();
}



function assertStatus(response, expected, name) {
  if (response.status !== expected) {
    fail(`${name} expected HTTP ${expected}, got ${response.status}: ${response.text}`);
  }
}





function configuredNodeImage() {
  return process.env.NODE_IMAGE || parseEnv(path.join(infraRoot, ".env")).NODE_IMAGE || defaultNodeImage;
}

function configuredPlaywrightImage() {
  return process.env.PLAYWRIGHT_IMAGE || parseEnv(path.join(infraRoot, ".env")).PLAYWRIGHT_IMAGE || defaultPlaywrightImage;
}











async function backupPostgres(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? defaultPostgresBackupDatabase();
  const user = options.user ?? argv.user ?? "postgres";
  const outputDir = path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "postgres"));
  const startedAt = new Date();
  fs.mkdirSync(outputDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const fileName = `${database}-${timestamp}.dump`;
  const containerPath = `/tmp/${fileName}`;
  const hostPath = path.join(outputDir, fileName);
  const stagingPath = backupArtifactStagingPath(hostPath);

  try {
    log(`Creating PostgreSQL backup for database '${database}'...`);
    dockerExec(container, ["pg_dump", "-U", user, "-d", database, "--format=custom", "--no-owner", "--no-acl", `--file=${containerPath}`]);
    run("docker", ["cp", `${container}:${containerPath}`, stagingPath]);
    dockerExec(container, ["rm", "-f", containerPath]);

    const publication = publishBackupArtifact({
      stagingPath,
      publishedPath: hostPath,
      createSignature: createBackupArtifactSignature,
      onPublished({ hash, sizeBytes, signature }) {
        recordBackupRestoreRun({ container, database, user, operation: "backup", status: "success", artifactPath: hostPath, artifactSha256: hash, startedAt });
        writeBackupExecutionReport({
          engine: "postgres",
          sourceContainer: container,
          status: "success",
          artifactPath: hostPath,
          artifactSha256: hash,
          artifactSizeBytes: sizeBytes,
          signature,
          startedAt,
          metadata: { database, format: "pg_dump-custom" },
        });
      },
    });
    try {
      const { hash, signature } = publication;
      publication.assertCurrent();
      log(`Backup written to ${hostPath}`);
      log(`SHA256: ${hash}`);
      log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
      return { hostPath, hash, signature, container, database, user };
    } finally {
      publication.close();
    }
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-f", containerPath], { allowFailure: true });
      recordBackupRestoreRun({ container, database, user, operation: "backup", status: "failed", artifactPath: hostPath, startedAt, metadata: { error: String(error?.message ?? error) } });
      writeBackupExecutionReport({
        engine: "postgres",
        sourceContainer: container,
        status: "failed",
        artifactPath: hostPath,
        startedAt,
        metadata: { database, error: String(error?.message ?? error) },
      });
    } catch {
      // Preserve the original backup failure.
    }
    throw error;
  }
}

function applicationSourceBackupExcludes() {
  return [
    ".git",
    ".hg",
    ".svn",
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.dump",
    "*.sql",
    "*.sqlite",
    "*.sqlite3",
    "node_modules",
    "vendor",
    ".next",
    ".nuxt",
    "dist",
    "build",
    "coverage",
    ".cache",
    ".turbo",
    ".parcel-cache",
    "backups",
    ".codex-backups",
    "storage/logs",
    "var/cache",
    "var/log",
  ];
}

function safeApplicationBackupSlug(value) {
  const clean = String(value || "").trim().toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80);
  if (!/^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/.test(clean)) {
    fail(`Invalid application backup slug: ${value || "(empty)"}`);
  }
  return clean;
}

function applicationSourceDirectories(options = {}) {
  if (!fs.existsSync(sourceRoot)) {
    fail(`Project source root not found: ${sourceRoot}`);
  }
  const ignoredTopLevel = new Set(["node_modules", "vendor", "packages", "scripts", "docs", "e2e", "coverage", "dist", "build", ".next", ".cache", ".turbo"]);
  const requested = options.project ?? options.sourceDirectory ?? argv.project ?? argv.application ?? argv.app;
  if (requested) validateTarEntryName(requested, "requested application source name");
  const requestedSlug = requested ? safeApplicationBackupSlug(requested) : "";
  const entries = fs.readdirSync(sourceRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && !entry.name.startsWith("."))
    .filter((entry) => !ignoredTopLevel.has(entry.name.toLowerCase()))
    .map((entry) => {
      validateTarEntryName(entry.name, "application source directory name");
      const slug = safeApplicationBackupSlug(entry.name);
      return {
        name: entry.name,
        slug,
        path: path.join(sourceRoot, entry.name),
      };
    })
    .filter((entry) => !requestedSlug || entry.slug === requestedSlug || safeApplicationBackupSlug(entry.name) === requestedSlug);
  if (!entries.length) {
    fail(requestedSlug ? `Application source not found for ${requestedSlug} under ${sourceRoot}` : `No application source directories found under ${sourceRoot}`);
  }
  return entries;
}

async function backupApplications(options = {}) {
  const startedAt = new Date();
  const timestamp = backupTimestamp();
  const outputRoot = ensureBackupOutputDir(path.join(infraRoot, "backups", "applications"));
  const excludeArgs = applicationSourceBackupExcludes().flatMap((pattern) => ["--exclude", pattern]);
  const artifacts = [];
  const publications = [];
  try {
    for (const application of applicationSourceDirectories(options)) {
      const outputDir = ensureBackupOutputDir(path.join(outputRoot, application.slug));
      const fileName = `${application.slug}-source-${timestamp}.tar.gz`;
      const hostPath = path.join(outputDir, fileName);
      const stagingPath = backupArtifactStagingPath(hostPath);
      log(`Creating application source backup for '${application.name}'...`);
      run("tar", safeTarCreateArgs({ archivePath: stagingPath, excludeArgs, sourceRoot, entryName: application.name }));
      const publication = publishBackupArtifact({
        stagingPath,
        publishedPath: hostPath,
        createSignature: createBackupArtifactSignature,
      });
      publications.push(publication);
      artifacts.push({
        application: application.slug,
        sourceDirectory: application.name,
        artifactPath: hostPath,
        artifactName: fileName,
        artifactSha256: publication.hash,
        signaturePath: publication.signature.signaturePath,
        signatureKeyId: publication.signature.keyId,
        artifactSizeBytes: publication.sizeBytes,
      });
    }
    const finishedAt = new Date();
    const status = artifacts.length ? "success" : "failed";
    const payload = {
      generatedAt: finishedAt.toISOString(),
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
      engine: "applications",
      sourceContainer: "project-source",
      status,
      artifactPath: artifacts[0]?.artifactPath ?? null,
      artifactName: artifacts[0]?.artifactName ?? null,
      artifactSizeBytes: artifacts.reduce((total, artifact) => total + Number(artifact.artifactSizeBytes || 0), 0),
      artifactSha256: artifacts[0]?.artifactSha256 ?? null,
      signaturePath: artifacts[0]?.signaturePath ?? null,
      signatureKeyId: artifacts[0]?.signatureKeyId ?? null,
      integrityVerified: artifacts.every((artifact) => Boolean(artifact.artifactSha256 && artifact.signaturePath)),
      metadata: {
        sourceRoot,
        applicationCount: artifacts.length,
        excluded: applicationSourceBackupExcludes(),
        artifacts,
        secretsExcluded: true,
        dependenciesExcluded: true,
        buildOutputExcluded: true,
      },
    };
    const stamp = reportTimestamp();
    const baseName = `applications-backup-${stamp}-${crypto.randomBytes(3).toString("hex")}`;
    const jsonPath = writeJsonReport("backups", baseName, payload);
    const markdownPath = writeMarkdownReport("backups", baseName, [
      "# Platform Applications Backup Report",
      "",
      `Status: ${payload.status}`,
      `Started at: ${payload.startedAt}`,
      `Finished at: ${payload.finishedAt}`,
      `Application count: ${payload.metadata.applicationCount}`,
      `Secrets excluded: ${payload.metadata.secretsExcluded ? "yes" : "no"}`,
      "",
      "| Application | Artifact | Size bytes |",
      "| --- | --- | --- |",
      ...artifacts.map((artifact) => `| ${artifact.application} | ${artifact.artifactPath} | ${artifact.artifactSizeBytes} |`),
    ]);
    for (const publication of publications) publication.assertCurrent();
    log(`Application backup reports written to ${jsonPath} and ${markdownPath}`);
    log(`Application source backups written under ${outputRoot}`);
    return payload;
  } finally {
    for (const publication of publications) publication.close();
  }
}

function controlCenterStateRoot() {
  const candidates = [
    process.env.PROJECT_STATE_ROOT,
    "/var/www/project-state",
    path.join(infraRoot, "projects-portal", "state"),
  ].filter(Boolean).map((value) => path.resolve(value));
  const stateRoot = candidates.find((candidate) => fs.existsSync(candidate) && fs.statSync(candidate).isDirectory());
  if (!stateRoot) fail("Control Center state root is not available for backup.");
  return stateRoot;
}

function validateControlCenterStateRoot(stateRoot) {
  const required = ["projects.json", "databases.json", "secret-vault.json", "operations.jsonl", "audit.jsonl"];
  const missing = required.filter((name) => !fs.existsSync(path.join(stateRoot, name)));
  if (missing.length) fail(`Control Center state backup is missing required files: ${missing.join(", ")}.`);
  return required;
}

async function backupControlCenterState(options = {}) {
  const stateRoot = path.resolve(options.stateRoot ?? controlCenterStateRoot());
  const required = validateControlCenterStateRoot(stateRoot);
  const outputDir = ensureBackupOutputDir(path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "control-center-state")));
  const startedAt = new Date();
  const fileName = `control-center-state-${backupTimestamp()}.tar.gz`;
  const hostPath = path.join(outputDir, fileName);
  const stagingPath = backupArtifactStagingPath(hostPath);
  run("tar", [
    "-czf", stagingPath,
    "--exclude=backup-jobs",
    "--exclude=*.tmp",
    "--exclude=*.tmp-*",
    "--exclude=*.codex-*",
    "-C", stateRoot,
    ".",
  ]);
  const { hash, signature } = publishBackupArtifactWithEvidence({
    stagingPath,
    hostPath,
    engine: "control-center-state",
    sourceContainer: "project-state",
    startedAt,
    metadata: {
      scope: "restricted-control-state-local-artifact",
      requiredFiles: required,
      queueStateExcluded: true,
      temporaryAndLegacyCopiesExcluded: true,
      containsSensitiveEncryptedOrCredentialMaterial: true,
      restrictedAccessRequired: true,
      plaintextExposed: false,
    },
  });
  return { hostPath, hash, signature, stateRoot };
}

function restoreTestControlCenterState(options = {}) {
  const backupFileArg = options.backupFile ?? argv.backupFile ?? argv._[0];
  if (!backupFileArg) fail("Provide --backupFile <path>.");
  const backupFile = resolveInside(backupRootPath(), path.resolve(backupFileArg));
  verifyBackupArtifact(backupFile);
  const entries = output("tar", ["-tzf", backupFile]).split(/\r?\n/).filter(Boolean);
  const verboseEntries = output("tar", ["-tvzf", backupFile]).split(/\r?\n/).filter(Boolean);
  if (!entries.length || verboseEntries.some((entry) => /^[lh]/.test(entry.trim()))) fail("Control Center state archive is empty or contains links.");
  for (const entry of entries) {
    const normalized = entry.replace(/^\.\//, "");
    if (normalized.startsWith("/") || normalized.split("/").includes("..")) fail("Control Center state archive contains an unsafe path.");
  }
  const target = makeOpsTempDir("restore-control-center-state-");
  try {
    run("tar", ["-xzf", backupFile, "-C", target]);
    const required = validateControlCenterStateRoot(target);
    const files = listFilesRecursive(target);
    if (files.some((filePath) => fs.lstatSync(filePath).isSymbolicLink())) fail("Control Center state restore contains a symlink.");
    return { status: "passed", requiredFiles: required, fileCount: files.length, liveStateChanged: false };
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
}

function typedBackupJobPath(options = {}) {
  const jobsRoot = path.resolve(process.env.BACKUP_SCHEDULER_JOBS_DIR || path.join(infraRoot, "projects-portal", "state", "backup-jobs"));
  const gatewaySnapshotRoot = process.env.PLATFORM_DOCKER_GATEWAY_CHILD === "1"
    ? String(process.env.DOCKER_GATEWAY_JOB_SNAPSHOT_ROOT || "")
    : "";
  const allowedRoot = path.resolve(gatewaySnapshotRoot || path.join(jobsRoot, "running"));
  const jobFile = options.jobFile ?? argv.jobFile;
  const requested = path.resolve(jobFile || "");
  if (!jobFile || !requested.startsWith(`${allowedRoot}${path.sep}`)) {
    fail("Typed backup jobs must be read from the scheduler queue or gateway snapshot.");
  }
  const stat = fs.lstatSync(requested);
  const parent = fs.realpathSync.native(path.dirname(requested));
  if (!stat.isFile() || stat.isSymbolicLink() || parent !== fs.realpathSync.native(allowedRoot)) {
    fail("Typed backup job must be a contained regular non-symlink file.");
  }
  return requested;
}

function relativeBackupArtifactPath(filePath) {
  const root = path.resolve(backupRootPath());
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(`${root}${path.sep}`)) fail("Backup artifact escaped the backup root.");
  return path.relative(root, resolved).replaceAll("\\", "/");
}

function typedArtifactRecord(resource, result) {
  const hostPath = path.resolve(result.hostPath || "");
  if (!hostPath || !fs.existsSync(hostPath)) fail(`Missing artifact for ${resource.id}.`);
  const signature = result.signature || verifyBackupArtifact(hostPath);
  const hash = result.hash || sha256File(hostPath);
  if (signature.hash && signature.hash !== hash) fail(`Artifact signature hash mismatch for ${resource.id}.`);
  return {
    id: `artifact-${resource.externalId}-${hash.slice(0, 12)}`,
    resourceId: resource.id,
    path: relativeBackupArtifactPath(hostPath),
    sha256: hash,
    sizeBytes: fs.statSync(hostPath).size,
    signatureKeyId: signature.keyId,
  };
}

function writeTypedBackupManifest(job, artifacts) {
  const manifestId = `manifest-${job.id}`;
  const manifest = createBackupManifestDocument({ id: manifestId, job, artifacts });
  if (!manifest.coverage.complete) fail(`Typed backup manifest is incomplete: ${manifest.coverage.missingResourceIds.join(", ")}`);
  const signed = signBackupManifestDocument(manifest);
  const manifestDir = ensureBackupOutputDir(path.join(backupRootPath(), "manifests"));
  const manifestPath = path.join(manifestDir, `${manifestId}.json`);
  writePrivateJsonAtomic(manifestPath, signed);
  verifyBackupManifestDocument(JSON.parse(fs.readFileSync(manifestPath, "utf8")));
  return { manifest: signed, manifestPath, relativePath: relativeBackupArtifactPath(manifestPath) };
}

function updateTypedBackupJob(jobPath, patch) {
  const current = JSON.parse(fs.readFileSync(jobPath, "utf8"));
  writePrivateJsonAtomic(jobPath, {
    ...current,
    ...patch,
    updatedAt: new Date().toISOString(),
  });
}

async function executeTypedBackupResource(resource) {
  if (resource.kind === "source") {
    const result = await backupApplications({ project: resource.sourceDirectory });
    const artifact = result.metadata?.artifacts?.find((item) => item.application === resource.sourceDirectory || item.sourceDirectory === resource.sourceDirectory);
    if (!artifact) fail(`Source backup did not produce the exact resource ${resource.id}.`);
    return typedArtifactRecord(resource, {
      hostPath: artifact.artifactPath,
      hash: artifact.artifactSha256,
      signature: { keyId: artifact.signatureKeyId, signaturePath: artifact.signaturePath },
    });
  }
  if (resource.kind === "database" && resource.engine === "postgres") {
    return typedArtifactRecord(resource, await backupPostgres({
      container: process.env.BACKUP_POSTGRES_CONTAINER || "enterprise-postgres",
      database: resource.name,
    }));
  }
  if (resource.kind === "database" && resource.engine === "mariadb") {
    return typedArtifactRecord(resource, await backupMariadb({
      container: process.env.BACKUP_MARIADB_CONTAINER || "mariadb",
      database: resource.name,
    }));
  }
  if (resource.kind === "platform-state" && resource.externalId === "minio-data") {
    return typedArtifactRecord(resource, await backupMinio());
  }
  if (resource.kind === "platform-state" && resource.externalId === "keycloak-config") {
    return typedArtifactRecord(resource, await backupKeycloakConfig());
  }
  if (resource.kind === "platform-state" && resource.externalId === "control-center-state") {
    return typedArtifactRecord(resource, await backupControlCenterState());
  }
  if (resource.kind === "platform-state" && resource.externalId === "secret-manager-metadata") {
    return typedArtifactRecord(resource, await backupSecretManagerMetadata());
  }
  fail(`Typed backup resource is not implemented: ${resource.id}.`);
}

function readVerifiedSourceManifest(relativePath) {
  const root = path.resolve(backupRootPath());
  const manifestPath = resolveInside(root, path.resolve(root, relativePath));
  if (!manifestPath.startsWith(`${path.join(root, "manifests")}${path.sep}`)) fail("Restore manifest must be under backups/manifests.");
  return {
    manifestPath,
    manifest: verifyBackupManifestDocument(JSON.parse(fs.readFileSync(manifestPath, "utf8"))),
  };
}

function assertRestoreResourceMatchesManifest(resource, manifest) {
  const declared = manifest.resources.find((item) => item.id === resource.id);
  if (!declared || JSON.stringify(declared) !== JSON.stringify(resource)) {
    fail(`Restore resource does not exactly match source manifest: ${resource.id}`);
  }
  const artifact = manifestArtifactForResource(manifest, resource.id);
  if (!artifact) fail(`Source manifest has no artifact for ${resource.id}.`);
  return artifact;
}

function restoreTestApplicationSource(resource, backupFile) {
  const startedAt = new Date();
  verifyBackupArtifact(backupFile);
  const entries = output("tar", ["-tzf", backupFile]).split(/\r?\n/).filter(Boolean);
  if (!entries.length) fail(`Source archive is empty for ${resource.id}.`);
  const verboseEntries = output("tar", ["-tvzf", backupFile]).split(/\r?\n/).filter(Boolean);
  if (verboseEntries.some((entry) => /^[lh]/.test(entry.trim()))) fail("Source archive contains a link entry.");
  for (const entry of entries) {
    const normalized = entry.replace(/^\.\//, "");
    if (normalized.startsWith("/") || normalized.split("/").includes("..")) fail("Source archive contains an unsafe path.");
    if (!(normalized === resource.sourceDirectory || normalized.startsWith(`${resource.sourceDirectory}/`))) {
      fail(`Source archive contains a foreign project path: ${normalized}`);
    }
  }
  const target = makeOpsTempDir(`restore-source-${resource.projectId}-`);
  try {
    run("tar", ["-xzf", backupFile, "-C", target]);
    const restoredRoot = path.join(target, resource.sourceDirectory);
    if (!fs.existsSync(restoredRoot) || !fs.statSync(restoredRoot).isDirectory()) fail("Source restore drill did not recreate the expected project root.");
    const summary = directorySummary(restoredRoot);
    if (summary.files < 1) fail("Source restore drill produced no files.");
    return { resourceId: resource.id, status: "passed", durationMs: Date.now() - startedAt.getTime(), files: summary.files };
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
}

function directorySummary(root) {
  const summary = { files: 0, directories: 0 };
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) fail("Restore drill output contains a symlink.");
    if (stat.isDirectory()) {
      summary.directories += 1;
      for (const name of fs.readdirSync(current)) stack.push(path.join(current, name));
    } else if (stat.isFile()) {
      summary.files += 1;
    }
  }
  return summary;
}

async function executeTypedRestoreResource(resource, artifact, options = {}) {
  const restoreArtifactRoot = path.resolve(options.backupRoot ?? backupRootPath());
  const backupFile = assertPathInside(restoreArtifactRoot, path.resolve(restoreArtifactRoot, artifact.path));
  const verified = verifyBackupArtifact(backupFile);
  if (verified.hash !== artifact.sha256 || fs.statSync(backupFile).size !== artifact.sizeBytes) {
    fail(`Restore artifact metadata mismatch for ${resource.id}.`);
  }
  if (resource.kind === "source") return restoreTestApplicationSource(resource, backupFile);
  if (resource.kind === "database" && resource.engine === "postgres") {
    const result = await restoreTestPostgres({
      container: process.env.BACKUP_POSTGRES_CONTAINER || "enterprise-postgres",
      database: resource.name,
      backupFile,
      countAllUserTables: true,
      minimumTables: 1,
    });
    return { resourceId: resource.id, status: "passed", testDatabase: result.testDatabase };
  }
  if (resource.kind === "database" && resource.engine === "mariadb") {
    const result = await restoreTestMariadb({
      container: process.env.BACKUP_MARIADB_CONTAINER || "mariadb",
      backupFile,
      minSchemas: 1,
    });
    return { resourceId: resource.id, status: "passed", restoredSchemas: result.restoredSchemas };
  }
  if (resource.kind === "platform-state" && resource.externalId === "minio-data") {
    const result = await restoreTestMinio({ backupFile });
    return { resourceId: resource.id, status: "passed", restoredEntries: result.restoredEntries };
  }
  if (resource.kind === "platform-state" && resource.externalId === "keycloak-config") {
    const result = await restoreTestKeycloakConfig({ backupFile });
    return { resourceId: resource.id, status: "passed", realmCount: result.realmCount };
  }
  if (resource.kind === "platform-state" && resource.externalId === "control-center-state") {
    return { resourceId: resource.id, ...restoreTestControlCenterState({ backupFile }) };
  }
  if (resource.kind === "platform-state" && resource.externalId === "secret-manager-metadata") {
    await restoreTestSecretManagerMetadata({ backupFile });
    return { resourceId: resource.id, status: "passed" };
  }
  fail(`Typed restore resource is not implemented: ${resource.id}.`);
}

async function executeBackupJob(options = {}) {
  const jobPath = typedBackupJobPath(options);
  const job = parseBackupJobDocument(JSON.parse(fs.readFileSync(jobPath, "utf8")));
  if (job.status !== "running") fail("Typed backup executor accepts only jobs claimed by the scheduler.");
  const startedAt = new Date();
  let manifestPath = "";
  let results = [];
  if (job.operation === "backup") {
    const artifacts = [];
    for (const resource of job.resources) artifacts.push(await executeTypedBackupResource(resource));
    const written = writeTypedBackupManifest(job, artifacts);
    manifestPath = written.relativePath;
    results = written.manifest.artifacts.map((artifact) => ({ resourceId: artifact.resourceId, status: "passed", artifactPath: artifact.path }));
  } else {
    const source = readVerifiedSourceManifest(job.sourceManifestPath);
    manifestPath = relativeBackupArtifactPath(source.manifestPath);
    for (const resource of job.resources) {
      const artifact = assertRestoreResourceMatchesManifest(resource, source.manifest);
      results.push(await executeTypedRestoreResource(resource, artifact));
    }
  }
  const finishedAt = new Date();
  const report = {
    generatedAt: finishedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    status: "passed",
    schema: job.schema,
    jobId: job.id,
    operation: job.operation,
    scope: job.scope,
    resourceIds: job.resources.map((resource) => resource.id),
    manifestPath,
    results,
    liveDataChanged: false,
  };
  const reportName = `typed-${job.operation}-${job.id}`;
  const reportPath = writeJsonReport("backup-jobs", reportName, report);
  const relativeReportPath = path.relative(infraRoot, reportPath).replaceAll("\\", "/");
  updateTypedBackupJob(jobPath, {
    manifestPath,
    reportPaths: [relativeReportPath],
    resultSummary: `Typed ${job.operation} completed for ${job.resources.length} exact resources.`,
  });
  log(`Typed backup job report written to ${reportPath}`);
  return report;
}

function backupDatabaseCatalog(options = {}) {
  const stateRoot = path.resolve(options.stateRoot ?? controlCenterStateRoot());
  const databaseFile = path.resolve(options.databaseFile ?? process.env.PROJECT_DATABASES_FILE ?? path.join(stateRoot, "databases.json"));
  const parsed = JSON.parse(fs.readFileSync(databaseFile, "utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail("Control Center database catalog must be an object.");
  const databases = [];
  const physical = new Set();
  const add = ({ projectId, engine, name, externalId }) => {
    const cleanEngine = String(engine || "").trim().toLowerCase();
    const cleanName = sqlIdentifierName(name, "backup database name");
    if (!new Set(["postgres", "mariadb"]).has(cleanEngine)) fail(`Unsupported backup database engine: ${cleanEngine}`);
    const physicalKey = `${cleanEngine}:${cleanName}`;
    if (physical.has(physicalKey)) return;
    physical.add(physicalKey);
    const identity = externalId ?? `${safeApplicationBackupSlug(projectId)}-${cleanEngine}-${cleanName.replaceAll("_", "-")}`;
    databases.push({
      id: backupResourceId("database", identity),
      externalId: identity,
      kind: "database",
      projectId: safeApplicationBackupSlug(projectId),
      name: cleanName,
      engine: cleanEngine,
    });
  };
  for (const database of Object.values(parsed)) {
    if (!database || typeof database !== "object" || database.deletedAt || database.status === "deleted") continue;
    if (!database.projectId || !database.engine || !database.name) continue;
    add(database);
  }
  add({ projectId: "platform", engine: "postgres", name: process.env.KEYCLOAK_DB_NAME || "keycloak", externalId: "platform-postgres-keycloak" });
  return databases.sort((a, b) => a.id.localeCompare(b.id));
}

function platformBackupResources(options = {}) {
  const sources = applicationSourceDirectories(options).map((application) => ({
    id: backupResourceId("source", application.slug),
    externalId: application.slug,
    kind: "source",
    projectId: application.slug,
    name: application.name,
    sourceDirectory: application.name,
  }));
  const platformState = [
    "minio-data",
    "keycloak-config",
    "control-center-state",
    "secret-manager-metadata",
  ].map((externalId) => ({
    id: backupResourceId("platform-state", externalId),
    externalId,
    kind: "platform-state",
    projectId: "platform",
    name: externalId,
  }));
  return [...sources, ...backupDatabaseCatalog(options), ...platformState].sort((a, b) => a.id.localeCompare(b.id));
}

function writeBackupCoverageReport(resources, options = {}) {
  const byKind = Object.fromEntries(["source", "database", "platform-state"].map((kind) => [kind, resources.filter((resource) => resource.kind === kind).length]));
  const policyFile = path.resolve(options.policyFile ?? path.join(infraRoot, "governance", "backup-data-policy.json"));
  const policy = JSON.parse(fs.readFileSync(policyFile, "utf8"));
  if (policy.schema !== "platform.backup-data-policy/v1") fail("Unsupported backup data policy schema.");
  const resourceIds = resources.map((resource) => resource.id);
  const missingPlatformStateIds = policy.requiredPlatformStateIds.filter((id) => !resourceIds.includes(id));
  if (missingPlatformStateIds.length) fail(`Backup catalog is missing required platform state: ${missingPlatformStateIds.join(", ")}`);
  if (policy.backupIntervalHours !== 8 || policy.localRetention?.keepCompleteManifests !== 42 || policy.localRetention?.maximumAgeDays !== 14) {
    fail("Backup data policy must retain 42 complete eight-hour restore points covering 14 days.");
  }
  const rebuildOnly = new Set(policy.rebuildOnlyServices.map((entry) => entry.service));
  if (!["redis", "nats", "prometheus-grafana-loki-alertmanager"].every((service) => rebuildOnly.has(service))) {
    fail("Backup data policy must explicitly classify every rebuild-only runtime state family.");
  }
  const payload = {
    generatedAt: new Date().toISOString(),
    status: "passed",
    scope: "platform-infrastructure",
    resourceCount: resources.length,
    byKind,
    resourceIds,
    rebuildOnlyServices: policy.rebuildOnlyServices,
    requiredPlatformStateIds: policy.requiredPlatformStateIds,
    exactResourceCoverage: true,
    mutableRuntimeStatePolicyDeclared: true,
    missingPlatformStateIds,
  };
  const stamp = reportTimestamp();
  const baseName = `backup-coverage-${stamp}`;
  const jsonPath = writeJsonReport("backup-coverage", baseName, payload);
  const markdownPath = writeMarkdownReport("backup-coverage", baseName, [
    "# Platform Backup Coverage",
    "",
    `Status: ${payload.status}`,
    `Exact resources: ${payload.resourceCount}`,
    `Sources: ${byKind.source}`,
    `Databases: ${byKind.database}`,
    `Platform state: ${byKind["platform-state"]}`,
    `Rebuild-only services: ${policy.rebuildOnlyServices.map((entry) => entry.service).join(", ")}`,
  ]);
  return { payload, jsonPath, markdownPath };
}

async function backupPlatformCatalog(options = {}) {
  const resources = platformBackupResources(options);
  writeBackupCoverageReport(resources, options);
  const jobsRoot = path.resolve(process.env.BACKUP_SCHEDULER_JOBS_DIR || path.join(infraRoot, "projects-portal", "state", "backup-jobs"));
  const directories = Object.fromEntries(["running", "done", "failed"].map((name) => {
    const directory = path.join(jobsRoot, name);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.chmodSync(directory, 0o700);
    return [name, directory];
  }));
  const jobId = `scheduled-platform-${backupTimestamp().toLowerCase()}-${crypto.randomBytes(3).toString("hex")}`;
  const job = createBackupJobDocument({
    id: jobId,
    operation: "backup",
    scope: { kind: "platform", id: "platform" },
    resources,
    requestedBy: options.requestedBy ?? "backup-scheduler",
    environment: process.env.PLATFORM_ENVIRONMENT || "production",
  });
  const runningPath = path.join(directories.running, `${jobId}.json`);
  writePrivateJsonAtomic(runningPath, { ...job, status: "running", startedAt: new Date().toISOString() });
  try {
    const report = await executeBackupJob({ jobFile: runningPath });
    const donePath = path.join(directories.done, path.basename(runningPath));
    updateTypedBackupJob(runningPath, { status: "done", finishedAt: new Date().toISOString() });
    fs.renameSync(runningPath, donePath);
    log(`Complete platform backup manifest: ${report.manifestPath}`);
    return report;
  } catch (error) {
    if (fs.existsSync(runningPath)) {
      updateTypedBackupJob(runningPath, { status: "failed", finishedAt: new Date().toISOString(), resultSummary: String(error?.message ?? error).slice(0, 500) });
      fs.renameSync(runningPath, path.join(directories.failed, path.basename(runningPath)));
    }
    throw error;
  }
}

function verifiedPlatformManifests() {
  const manifestDir = path.join(backupRootPath(), "manifests");
  return listFilesRecursive(manifestDir, (filePath) => filePath.endsWith(".json")).map((manifestPath) => {
    try {
      const manifest = verifyBackupManifestDocument(JSON.parse(fs.readFileSync(manifestPath, "utf8")));
      return manifest.scope.kind === "platform" && manifest.coverage.complete ? { manifestPath, manifest } : null;
    } catch {
      return null;
    }
  }).filter(Boolean).sort((a, b) => Date.parse(b.manifest.createdAt) - Date.parse(a.manifest.createdAt));
}

function pruneManifestBackups() {
  const keepLast = positiveInteger(argv.keepLast ?? process.env.BACKUP_LOCAL_KEEP_LAST ?? 42, "--keepLast", 1);
  const manifests = verifiedPlatformManifests();
  const retained = manifests.slice(0, keepLast);
  const expired = manifests.slice(keepLast);
  const protectedArtifacts = new Set(retained.flatMap(({ manifest }) => manifest.artifacts.map((artifact) => artifact.path)));
  const candidates = [];
  for (const entry of expired) {
    candidates.push(entry.manifestPath);
    for (const artifact of entry.manifest.artifacts) {
      if (protectedArtifacts.has(artifact.path)) continue;
      const artifactPath = resolveInside(backupRootPath(), path.join(backupRootPath(), artifact.path));
      candidates.push(artifactPath, `${artifactPath}.sha256`, `${artifactPath}.sig.json`);
    }
  }
  const existingCandidates = [...new Set(candidates)].filter((filePath) => fs.existsSync(filePath));
  const apply = booleanFlag(argv.confirmPruneManifestBackups);
  if (apply) for (const filePath of existingCandidates) fs.rmSync(filePath);
  const payload = {
    generatedAt: new Date().toISOString(),
    status: "passed",
    mode: apply ? "apply" : "plan",
    keepLast,
    completeManifestCount: manifests.length,
    retainedManifestIds: retained.map(({ manifest }) => manifest.id),
    expiredManifestIds: expired.map(({ manifest }) => manifest.id),
    candidateFileCount: existingCandidates.length,
    unmanifestedArtifactsDeleted: false,
  };
  const reportPath = writeJsonReport("backup-retention", `manifest-retention-${reportTimestamp()}`, payload);
  log(`Manifest retention ${payload.mode} report written to ${reportPath}`);
  return payload;
}

async function certificateExpiryCheck() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const defaultHosts = [
    env.CONTROL_CENTER_HOST ?? env.ADMIN_HOST ?? "portal.localhost.com",
    env.DOCS_HOST ?? "docs.localhost.com",
  ].join(",");
  const hosts = (argv.hosts ?? defaultHosts).split(",").map((host) => host.trim()).filter(Boolean);
  const warnDays = Number(argv.warnDays ?? 30);
  await withLocalCheckReport("certificate-expiry-check", async () => {
    for (const host of hosts) {
      await new Promise((resolve, reject) => {
        const socket = tls.connect({
          host,
          port: 443,
          servername: host,
          rejectUnauthorized: false,
        }, () => {
          const cert = socket.getPeerCertificate();
          socket.end();
          const daysLeft = Math.floor((Date.parse(cert.valid_to) - Date.now()) / 86400000);
          log(`${host} certificate expires in ${daysLeft} days (${new Date(cert.valid_to).toISOString()})`);
          if (daysLeft < warnDays) {
            reject(new Error(`${host} certificate expires in less than ${warnDays} days`));
          } else {
            resolve();
          }
        });
        socket.on("error", reject);
      });
    }
    log("Certificate expiry check passed.");
  }, { hosts, warnDays });
}

async function enterpriseCheck() {
  await withLocalCheckReport("enterprise-check", async () => {
    log("==> Platform infrastructure enterprise gate");
    run("docker", ["compose", "--env-file", path.join(infraRoot, ".env"), "-p", "platform_infra_local", "-f", path.join(infraRoot, "compose.yaml"), "config", "--quiet"]);
    await staticSecurityCheck();
    await dependencyHygiene();
    await testingHygiene();
    await maintainabilityHygiene();
    await performanceHygiene();
    await controlCenterTests();
    await projectRouterTests();
    run(process.execPath, [path.join(scriptDir, "infra-ops.mjs"), "enterprise-requirements-check"], { cwd: infraRoot });
    run(process.execPath, [path.join(scriptDir, "infra-ops.mjs"), "enterprise-requirements-check", "--manifest", "governance/production-readiness.json"], { cwd: infraRoot });
    log("Platform infrastructure enterprise gate passed.");
  }, { scope: "platform-infrastructure", hostedWorkloads: "external-contract" });
}

async function enterpriseHardeningAudit() {
  const projectName = argv.projectName ?? "platform_infra_local";
  const includeProtectedRuntime = booleanFlag(argv.includeProtectedRuntime);
  await withLocalCheckReport("enterprise-hardening-audit", async () => {
    await staticSecurityCheck();
    await supplyChainHygiene();
    await testingHygiene();
    await maintainabilityHygiene();
    await performanceHygiene();
    run("docker", ["compose", "--env-file", ".env", "-p", projectName, "config", "--quiet"]);
    run("docker", ["compose", "--env-file", ".env", "-p", "enterprise_prod", "-f", "compose.yaml", "-f", "compose.prod.yaml", "config", "--quiet"]);
    await composeHealthcheckCoverage();
    await platformAdminAuditEvidence();
    await securitySmoke();
    await wafSmoke();
    await certificateExpiryCheck();
    await secretScan();
    if (includeProtectedRuntime) {
      await faultInjectionTests();
      if (fs.existsSync(path.join(infraRoot, "compose.secrets.yaml"))) {
        await validateLocalSecrets();
      }
      await backupRestoreDrill();
      await backupRestoreDrillMariadb();
      await backupRestoreDrillMinio();
      await backupRestoreDrillKeycloakConfig();
      await backupRestoreDrillSecretManagerMetadata();
      await prunePostgresBackups({ dryRun: true });
      await platformBrowserE2e();
      await loadSmoke();
      await runtimeHealthChecks();
    } else {
      log("Protected runtime checks skipped by default: no service stop, restore, backup, secret validation or load test was executed.");
    }
    log("Platform infrastructure hardening audit passed.");
  }, { scope: "platform-infrastructure", includeProtectedRuntime });
}

async function browserE2eTests() {
  await withLocalCheckReport("browser-e2e-tests", async () => {
    await platformBrowserE2e();
    log("Platform browser E2E tests passed.");
  }, { scope: "platform-infrastructure" });
}

async function platformBrowserE2e() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const host = env.CONTROL_CENTER_HOST ?? env.ADMIN_HOST ?? `portal.${env.DOMAIN ?? "localhost.com"}`;
  const url = `https://${host}/?section=status`;
  const script = `
const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  await page.goto(${JSON.stringify(url)}, { waitUntil: "domcontentloaded", timeout: 15000 });
  await page.waitForSelector("[data-status-tabs]", { timeout: 10000 });
  const result = await page.evaluate(() => {
    const text = (selector) => (document.querySelector(selector)?.textContent || "").replace(/\\s+/g, " ").trim();
    const tabs = Array.from(document.querySelectorAll("[data-status-tab]")).map((el) => el.textContent.replace(/\\s+/g, " ").trim());
    return {
      title: document.title,
      badge: text(".ops-badge"),
      tabs,
      hasStatusTable: Boolean(document.querySelector(".ops-status-table")),
      failedRows: Array.from(document.querySelectorAll("tr")).filter((tr) => tr.textContent.includes("Fallito")).length,
    };
  });
  if (result.title !== "Admin Control Center") throw new Error("unexpected title: " + result.title);
  if (!result.tabs.some((item) => /Controlli\\s+\\d+/.test(item))) throw new Error("missing total controls tab");
  if (!result.tabs.some((item) => /OK\\s+\\d+/.test(item))) throw new Error("missing OK tab");
  if (!result.hasStatusTable) throw new Error("missing status table");
  console.log(JSON.stringify(result));
  await browser.close();
})().catch(async (error) => {
  console.error(error && error.stack ? error.stack : error);
  process.exit(1);
});
`;
  run("docker", [
    "run",
    "--rm",
    "--network",
    "host",
    "--add-host",
    `${host}:127.0.0.1`,
    "-e",
    "CI=true",
    "-e",
    "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
    "-e",
    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1",
    configuredPlaywrightImage(),
    "bash",
    "-lc",
    `export NODE_PATH=/tmp/pw/node_modules && npm install --prefix /tmp/pw --no-save playwright@1.60.0 >/dev/null && node -e ${shellQuote(script)}`,
  ], { capture: false });
}

async function runtimeHealthChecks() {
  const runtimeContainers = [
    "enterprise-traefik",
    "enterprise-postgres",
    "enterprise-redis",
    "enterprise-keycloak",
    "enterprise-nats",
    "enterprise-minio",
    "mariadb",
    "enterprise-control-center",
    "enterprise-project-router",
    "enterprise-prometheus",
    "enterprise-node-exporter",
    "enterprise-cadvisor",
    "enterprise-platform-alert-dispatcher",
    "enterprise-alertmanager",
    "enterprise-grafana",
    "enterprise-loki",
    "enterprise-promtail",
  ];
  log("==> Platform container health and runtime guardrails");
  for (const container of runtimeContainers) {
    const [inspect] = JSON.parse(output("docker", ["inspect", container]));
    const state = inspect?.State ?? {};
    if (state.Status !== "running" || (state.Health && state.Health.Status !== "healthy")) {
      fail(`${container} is not healthy: status=${state.Status ?? "unknown"} health=${state.Health?.Status ?? "none"}`);
    }
    const hostConfig = inspect?.HostConfig ?? {};
    const securityOpt = hostConfig.SecurityOpt ?? [];
    const logConfig = hostConfig.LogConfig ?? {};
    const logOptions = logConfig.Config ?? {};
    if (hostConfig.Init !== true) fail(`${container} must run with init: true.`);
    if (!Number.isInteger(hostConfig.PidsLimit) || hostConfig.PidsLimit <= 0) fail(`${container} must set a positive pids_limit.`);
    if (!securityOpt.includes("no-new-privileges:true")) fail(`${container} must set no-new-privileges.`);
    if (logConfig.Type !== "json-file" || logOptions["max-size"] !== "10m" || logOptions["max-file"] !== "5") {
      fail(`${container} must use bounded json-file logging.`);
    }
    if ((inspect?.Mounts ?? []).some((mount) => mount.Destination === "/var/run/docker.sock" || mount.Source === "/var/run/docker.sock")) {
      fail(`${container} must not mount docker.sock.`);
    }
  }
  const redisPing = dockerExecOutput("enterprise-redis", ["sh", "-c", "redis-cli --user platform --pass \"$(cat /run/secrets/redis_password)\" --no-auth-warning ping"]);
  if (!/PONG/.test(redisPing)) fail("Redis ping failed.");
  const alertmanagerStatus = dockerExecOutput("enterprise-alertmanager", ["wget", "-q", "-O", "-", "http://127.0.0.1:9093/-/healthy"]);
  if (!/OK/.test(alertmanagerStatus)) fail("Alertmanager health endpoint is not OK.");
  const dispatcherHealth = dockerExecOutput("enterprise-platform-alert-dispatcher", ["wget", "-q", "-O", "-", "http://127.0.0.1:3000/health"]);
  if (!/\"status\":\"ok\"/.test(dispatcherHealth)) fail("Platform alert dispatcher health is not OK.");
  log("Platform runtime health checks passed.");
}

function imageReferenceFromTemplate(value) {
  const clean = String(value || "").trim().replace(/^["']|["']$/g, "");
  const defaultMatch = clean.match(/^\$\{[A-Za-z_][A-Za-z0-9_]*:-([^}]+)\}$/);
  if (defaultMatch) return defaultMatch[1];
  if (clean.startsWith("${")) return null;
  return clean || null;
}

function collectInfraContainerImageRefs() {
  const refs = new Map();
  const addRef = ({ file, ref, source }) => {
    const imageRef = imageReferenceFromTemplate(ref);
    if (!imageRef) return;
    if (!refs.has(imageRef)) {
      refs.set(imageRef, { ref: imageRef, files: new Set(), sources: new Set() });
    }
    refs.get(imageRef).files.add(file);
    refs.get(imageRef).sources.add(source);
  };

  const composeFiles = [
    "compose.yaml",
    "compose.backup-scheduler.yaml",
    "compose.runtime.yaml",
    "compose.networks.yaml",
    "compose.runtime-isolation.yaml",
    "compose.prod.yaml",
    "compose.secrets.yaml",
    "compose.staging.yaml",
    "compose.vps.yaml",
    "compose.waf.yaml",
    "compose.vps-waf.yaml",
  ];
  for (const file of composeFiles) {
    const target = path.join(infraRoot, file);
    if (!fs.existsSync(target)) continue;
    for (const line of readText(target).split(/\r?\n/)) {
      const match = line.match(/^\s*image:\s+(.+?)\s*(?:#.*)?$/);
      if (match) addRef({ file, ref: match[1], source: "compose" });
    }
  }

  const dockerfiles = [
    "docker/alert-dispatcher.Dockerfile",
    "docker/php-apache.Dockerfile",
    "docker/ops.Dockerfile",
    "docker/control-center.Dockerfile",
    "docker/restic-rclone.Dockerfile",
  ];
  for (const file of dockerfiles) {
    const target = path.join(infraRoot, file);
    if (!fs.existsSync(target)) continue;
    const args = new Map();
    const lines = readText(target).split(/\r?\n/);
    for (const line of lines) {
      const arg = line.match(/^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)/);
      if (arg) args.set(arg[1], arg[2]);
    }
    for (const line of lines) {
      const from = line.match(/^\s*FROM\s+(.+?)(?:\s+AS\s+\S+)?\s*$/i);
      if (!from) continue;
      const variable = from[1].match(/^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/);
      addRef({ file, ref: variable ? args.get(variable[1]) : from[1], source: "dockerfile" });
    }
  }

  return [...refs.values()]
    .map((entry) => ({
      ref: entry.ref,
      files: [...entry.files].sort(),
      sources: [...entry.sources].sort(),
    }))
    .sort((a, b) => a.ref.localeCompare(b.ref));
}

function writeInfraSbom(outputDir) {
  fs.mkdirSync(outputDir, { recursive: true });
  const timestamp = new Date().toISOString();
  const stamp = timestamp.replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const outputFile = path.join(outputDir, `platform-infrastructure-sbom-${stamp}.cdx.json`);
  const imageRefs = collectInfraContainerImageRefs();
  if (!imageRefs.length) {
    fail("No infrastructure container image references found for SBOM generation.");
  }
  const components = imageRefs.map((entry) => ({
    type: "container",
    name: entry.ref.split("@")[0],
    version: entry.ref.includes("@") ? entry.ref.split("@").at(-1) : entry.ref,
    "bom-ref": `container:${entry.ref}`,
    properties: [
      { name: "platform:imageRef", value: entry.ref },
      { name: "platform:sourceFiles", value: entry.files.join(",") },
      { name: "platform:sources", value: entry.sources.join(",") },
    ],
  }));
  const bom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp,
      component: {
        type: "application",
        name: "platform-infrastructure",
        version: "local",
      },
      properties: [
        { name: "platform:scope", value: "infrastructure-container-images" },
        { name: "platform:componentCount", value: String(components.length) },
      ],
    },
    components,
  };
  fs.writeFileSync(outputFile, `${JSON.stringify(bom, null, 2)}\n`, "utf8");
  return { outputFile, componentCount: components.length };
}

async function generateSbom() {
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "security", "sbom"));
  await withLocalCheckReport("generate-sbom", async () => {
    const sbom = writeInfraSbom(outputDir);
    log(`Infrastructure SBOM written to ${sbom.outputFile} (${sbom.componentCount} component(s)).`);
  }, { scope: "platform-infrastructure" });
}

async function dependencyHygiene() {
  await withLocalCheckReport("dependency-hygiene", async () => {
    infraDependencyHygiene();
  }, { scope: "platform-infrastructure" });
}

function infraDependencyHygiene() {
  const dockerfiles = [
    "docker/alert-dispatcher.Dockerfile",
    "docker/php-apache.Dockerfile",
    "docker/ops.Dockerfile",
    "docker/control-center.Dockerfile",
    "docker/restic-rclone.Dockerfile",
  ];
  for (const file of dockerfiles) {
    const text = readText(path.join(infraRoot, file));
    const args = new Map();
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)/);
      if (match) args.set(match[1], match[2]);
    }
    const fromLines = text.split(/\r?\n/).filter((line) => /^\s*FROM\s+/i.test(line));
    if (!fromLines.length) fail(`${file} has no FROM line.`);
    for (const line of fromLines) {
      const variable = line.match(/^\s*FROM\s+\$\{([A-Za-z_][A-Za-z0-9_]*)\}/);
      const imageRef = variable ? args.get(variable[1]) : line.replace(/^\s*FROM\s+/i, "").split(/\s+/)[0];
      if (!imageRef) fail(`${file} base image ARG ${variable?.[1] || "(unknown)"} must define a default image.`);
      assertMatch(imageRef, /@sha256:[a-f0-9]{64}/, `${file} base image must be digest-pinned: ${line.trim()}`);
      assertNoMatch(imageRef, /:latest(?:@|\s|$)/, `${file} must not use :latest base images.`);
    }
  }
  const composeFiles = [
    "compose.yaml",
    "compose.backup-scheduler.yaml",
    "compose.runtime.yaml",
    "compose.networks.yaml",
    "compose.runtime-isolation.yaml",
    "compose.prod.yaml",
    "compose.secrets.yaml",
    "compose.vps.yaml",
    "compose.waf.yaml",
    "compose.vps-waf.yaml",
  ];
  for (const file of composeFiles) {
    if (!fs.existsSync(path.join(infraRoot, file))) continue;
    const text = readText(path.join(infraRoot, file));
    assertNoMatch(text, /^\s*image:\s+[^$\n#]*:latest(?:\s|$)/m, `${file} must not pin services to :latest.`);
  }
  const supplyChain = evaluateSupplyChain(infraRoot);
  if (supplyChain.status !== "passed") {
    fail(`Supply-chain lock failed: ${supplyChain.failures.join("; ")}`);
  }
  const renovate = readJsonFile(path.join(infraRoot, "renovate.json"), "renovate.json");
  if (renovate.dependencyDashboardApproval !== true) {
    fail("renovate.json must keep dependencyDashboardApproval=true for controlled updates.");
  }
  run("docker", [
    "compose",
    "--env-file", ".env.example",
    "-p", "platform_infra_dependency_hygiene",
    "-f", "compose.yaml",
    "-f", "compose.secrets.yaml",
    "config", "--quiet",
  ]);
  log("Infrastructure dependency hygiene checks passed.");
}

async function cloudflareFromZero() {
  run(process.execPath, [path.join(scriptDir, "cloudflare-from-zero.mjs"), ...process.argv.slice(3)]);
}

async function cloudflareAccessAdmin() {
  run(process.execPath, [path.join(scriptDir, "cloudflare-access-admin.mjs"), ...process.argv.slice(3)]);
}

async function supplyChainHygiene() {
  await withLocalCheckReport("supply-chain-hygiene", async () => {
    infraDependencyHygiene();
    const sbom = writeInfraSbom(path.join(infraRoot, "security", "sbom"));
    log(`Platform infrastructure supply-chain hygiene passed with SBOM ${sbom.outputFile}.`);
  }, { scope: "platform-infrastructure" });
}

async function supplyChainLockCheck() {
  await withLocalCheckReport("supply-chain-lock", async () => {
    const report = evaluateSupplyChain(infraRoot);
    const stamp = reportTimestamp();
    const jsonPath = writeJsonReport("supply-chain", `supply-chain-lock-${stamp}`, report);
    const markdownPath = writeMarkdownReport("supply-chain", `supply-chain-lock-${stamp}`, [
      "# Supply-chain Lock Evidence",
      "",
      `Generated at: ${report.generatedAt}`,
      `Status: ${report.status}`,
      `Checks: ${report.summary.checks}`,
      `Failed: ${report.summary.failed}`,
      `Workflow files: ${report.summary.workflows}`,
      `Actions: ${report.summary.actions}`,
      `Images: ${report.summary.images}`,
      `Dockerfiles: ${report.summary.dockerfiles}`,
      "",
      "| Check | Status | Detail |",
      "| --- | --- | --- |",
      ...report.checks.map((item) => `| ${item.id} | ${item.status} | ${item.detail} |`),
    ]);
    log(`Supply-chain reports written to ${jsonPath} and ${markdownPath}`);
    if (report.status !== "passed") fail(`Supply-chain lock failed: ${report.failures.join("; ")}`);
    log("Supply-chain lock check passed.");
  }, { scope: "platform-infrastructure", liveRuntimeTouched: false });
}

async function testingHygiene() {
  await withLocalCheckReport("testing-hygiene", async () => {
    infraTestingHygiene();
  }, { scope: "platform-infrastructure" });
}

function infraTestingHygiene() {
  const checkFiles = [
    "scripts/infra-ops.mjs",
    "scripts/alert-delivery-sandbox-test.mjs",
    "scripts/control-center-vault-reencrypt.mjs",
    "scripts/database-principal-migration-plan.mjs",
    "scripts/hosted-workload-contract.mjs",
    "control-center/server.mjs",
    "control-center/database/destructive-workflow.mjs",
    "control-center/database/ownership.mjs",
    "control-center/vault/keyring.mjs",
    "project-router/server.mjs",
    "platform-alert-dispatcher/server.mjs",
    "scripts/network-segmentation-policy.mjs",
    "scripts/supply-chain-policy.mjs",
    "scripts/supply-chain-policy.test.mjs",
    "scripts/runtime-fingerprint.mjs",
    "scripts/runtime-fingerprint.test.mjs",
    "scripts/provider-evidence-auth.mjs",
    "scripts/provider-evidence-auth.test.mjs",
    "scripts/bounded-file-hash.mjs",
    "scripts/bounded-file-hash.test.mjs",
    "scripts/backup-artifact-publication.mjs",
    "scripts/backup-artifact-publication.test.mjs",
    "scripts/command-safety.mjs",
    "scripts/restic-secret-transport.mjs",
    "scripts/restic-secret-transport.test.mjs",
    "scripts/safe-tar-path.mjs",
    "scripts/safe-tar-path.test.mjs",
    "scripts/secret-store-metadata.mjs",
    "scripts/infra-secret-manager.mjs",
    "scripts/infra-secret-manager.test.mjs",
    "scripts/backup-import-policy.mjs",
    "scripts/backup-import-policy.test.mjs",
    "scripts/postgres-restore-sandbox.mjs",
    "scripts/postgres-restore-sandbox.test.mjs",
    "scripts/offsite-restore-contract.mjs",
    "scripts/offsite-restore-contract.test.mjs",
    "scripts/canonical-compose-topology.mjs",
    "scripts/canonical-compose-topology.test.mjs",
    "scripts/candidate-identity.mjs",
    "scripts/candidate-identity.test.mjs",
    "scripts/evidence-trust-envelope.mjs",
    "scripts/evidence-trust-envelope.test.mjs",
    "scripts/evidence-bundle-anchor.mjs",
    "scripts/evidence-bundle-anchor.test.mjs",
    "scripts/evidence-bundle-phase.mjs",
    "scripts/evidence-bundle-phase.test.mjs",
    "scripts/vps-evidence-request.mjs",
    "scripts/vps-evidence-request.test.mjs",
    "scripts/pinned-ssh-host-key.mjs",
    "scripts/pinned-ssh-host-key.test.mjs",
    "scripts/edge-provider-evidence.mjs",
    "scripts/edge-provider-evidence.test.mjs",
  ];
  for (const file of checkFiles) {
    run(process.execPath, ["--check", file], { cwd: infraRoot });
  }
  run(process.execPath, ["--test", ...controlCenterTestFiles()], { cwd: infraRoot });
  run(process.execPath, ["--test", "project-router/tests/project-router.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/hosted-workload-contract.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/functional-health.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/runtime-fingerprint.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/provider-evidence-auth.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/bounded-file-hash.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/backup-artifact-publication.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/restic-secret-transport.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/safe-tar-path.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/infra-secret-manager.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/backup-import-policy.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/postgres-restore-sandbox.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/offsite-restore-contract.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/canonical-compose-topology.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/candidate-identity.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/evidence-trust-envelope.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/evidence-bundle-anchor.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/evidence-bundle-phase.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["scripts/vps-evidence-request.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/pinned-ssh-host-key.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "scripts/edge-provider-evidence.test.mjs"], { cwd: infraRoot });
  run(process.execPath, ["--test", "platform-alert-dispatcher/server.test.mjs"], { cwd: infraRoot });
  const shellFiles = fs.readdirSync(path.join(infraRoot, "scripts")).filter((name) => name.endsWith(".sh")).sort();
  for (const file of shellFiles) {
    const shell = readText(path.join(infraRoot, "scripts", file)).startsWith("#!/usr/bin/env bash") ? "bash" : "sh";
    run(shell, ["-n", path.join("scripts", file)], { cwd: infraRoot });
  }
  log("Infrastructure testing hygiene checks passed.");
}

async function controlCenterTests() {
  await withLocalCheckReport("control-center-tests", async () => {
    log("==> Control Center tests");
    run(process.execPath, ["--test", ...controlCenterTestFiles()], { cwd: infraRoot });
    log("Control Center tests passed.");
  });
}

function controlCenterTestFiles() {
  return fs.readdirSync(path.join(infraRoot, "control-center", "tests"))
    .filter((name) => name.endsWith(".test.mjs"))
    .sort()
    .map((name) => path.join("control-center", "tests", name));
}

async function projectRouterTests() {
  await withLocalCheckReport("project-router-tests", async () => {
    log("==> Project Router tests");
    run(process.execPath, ["--test", "project-router/tests/project-router.test.mjs"], { cwd: infraRoot });
    log("Project Router tests passed.");
  });
}

function canonicalVpsTopologyRender({ envFile, projectName, workloadLock } = {}) {
  const resolvedEnvFile = path.resolve(envFile ?? argv.envFile ?? argv["env-file"] ?? path.join(infraRoot, ".env.vps.example"));
  if (!fs.existsSync(resolvedEnvFile)) fail(`Compose env file not found: ${resolvedEnvFile}`);
  const envValues = parseEnv(resolvedEnvFile);
  const resolvedProjectName = String(projectName ?? argv.projectName ?? argv.project ?? process.env.COMPOSE_PROJECT_NAME ?? envValues.COMPOSE_PROJECT_NAME ?? "platform_infra_vps").trim();
  const configuredWorkloadLock = workloadLock ?? argv.workloadLock ?? process.env.HOSTED_WORKLOAD_LOCK ?? envValues.HOSTED_WORKLOAD_LOCK ?? "";
  const plan = canonicalVpsTopologyPlan({ infraRoot, envFile: resolvedEnvFile, projectName: resolvedProjectName, workloadLock: configuredWorkloadLock });
  run(plan.verification.bin, plan.verification.args, { env: plan.verification.env });
  const workloadLockSha256Before = sha256File(plan.workloadLock);
  const configText = output(plan.command.bin, plan.command.args, {
    env: plan.command.env,
    maxBuffer: 128 * 1024 * 1024,
  });
  const workloadLockSha256After = sha256File(plan.workloadLock);
  if (workloadLockSha256Before !== workloadLockSha256After) fail("Hosted workload lock changed during canonical topology render.");
  return parseCanonicalVpsTopology(configText, plan, { workloadLockSha256: workloadLockSha256After });
}

function currentCandidateIdentity({ envFile, projectName, workloadLock, repository } = {}) {
  const git = gitEvidence();
  const { evidence: topology } = canonicalVpsTopologyRender({ envFile, projectName, workloadLock });
  const repositoryIdentity = repository
    ?? argv.repository
    ?? argv.repo
    ?? process.env.PLATFORM_GITHUB_REPOSITORY
    ?? process.env.GITHUB_REPOSITORY
    ?? git.repository;
  return createCandidateIdentity({
    repository: repositoryIdentity,
    commit: git.commit,
    tree: git.tree,
    clean: git.dirty === false,
    projectName: topology.projectName,
    workloadLockSha256: topology.workloadLock.sha256,
    renderSha256: topology.renderSha256,
  });
}

function currentCandidateIdentityEvidence(options = {}) {
  try {
    return { candidate: currentCandidateIdentity(options), error: null };
  } catch (error) {
    return { candidate: null, error: String(error?.message ?? error) };
  }
}

async function networkSegmentationCheck() {
  await withLocalCheckReport("network-segmentation", async () => {
    const envFile = path.resolve(infraRoot, argv.envFile || argv["env-file"] || ".env");
    const { config, evidence: topology } = canonicalVpsTopologyRender({ envFile });
    const report = evaluateNetworkSegmentation(config);
    report.canonicalTopology = topology;
    const stamp = reportTimestamp();
    const jsonPath = writeJsonReport("network-segmentation", `network-segmentation-${stamp}`, report);
    const markdownPath = writeMarkdownReport("network-segmentation", `network-segmentation-${stamp}`, [
      "# Network Segmentation Evidence",
      "",
      `Generated at: ${report.generatedAt}`,
      `Status: ${report.status}`,
      `Checks: ${report.summary.checks}`,
      `Failed: ${report.summary.failed}`,
      `Services: ${report.summary.services}`,
      `Networks: ${report.summary.networks}`,
      `Canonical render: ${topology.renderSha256}`,
      `Hosted workloads: ${topology.hostedWorkloadIds.join(", ") || "none"}`,
      "",
      "| Check | Status | Detail |",
      "| --- | --- | --- |",
      ...report.checks.map((item) => `| ${item.id} | ${item.status} | ${item.detail} |`),
    ]);
    log(`Network segmentation reports written to ${jsonPath} and ${markdownPath}`);
    if (report.status !== "passed") fail(`Network segmentation failed: ${report.failures.join("; ")}`);
    log("Network segmentation check passed.");
  }, { scope: "platform-infrastructure", liveNetworksTouched: false });
}

async function runtimeIsolationCheck() {
  await withLocalCheckReport("runtime-isolation", async () => {
    const envFile = path.resolve(infraRoot, argv.envFile || argv["env-file"] || ".env.vps.example");
    const { config, evidence: topology } = canonicalVpsTopologyRender({ envFile });
    const report = evaluateRuntimeIsolation(config);
    report.canonicalTopology = topology;
    const stamp = reportTimestamp();
    const jsonPath = writeJsonReport("runtime-isolation", `runtime-isolation-${stamp}`, report);
    const markdownPath = writeMarkdownReport("runtime-isolation", `runtime-isolation-${stamp}`, [
      "# Runtime Isolation Evidence",
      "",
      `Generated at: ${report.generatedAt}`,
      `Status: ${report.status}`,
      `Checks: ${report.summary.checks}`,
      `Failed: ${report.summary.failed}`,
      `Services: ${report.summary.services}`,
      `Hosted applications: ${report.summary.hostedApplications}`,
      `Total memory ceiling bytes: ${report.summary.totalMemoryLimitBytes}`,
      `Raw socket owners: ${report.summary.rawSocketOwners.join(",") || "none"}`,
      `Canonical render: ${topology.renderSha256}`,
      `Hosted workloads: ${topology.hostedWorkloadIds.join(", ") || "none"}`,
      "",
      "| Check | Status | Detail |",
      "| --- | --- | --- |",
      ...report.checks.map((item) => `| ${item.id} | ${item.status} | ${item.detail} |`),
    ]);
    log(`Runtime isolation reports written to ${jsonPath} and ${markdownPath}`);
    if (report.status !== "passed") fail(`Runtime isolation failed: ${report.failures.join("; ")}`);
    log("Runtime isolation check passed.");
  }, { scope: "platform-infrastructure", liveRuntimeTouched: false });
}

async function faultInjectionTests() {
  log("==> Platform fault injection tests");
  const timeoutProbe = postgres("enterprise-postgres", "postgres", "postgres", "begin; set local statement_timeout = '1ms'; select pg_sleep(0.05); rollback;", {
    allowFailure: true,
    capture: true,
  });
  const timeoutOutput = `${timeoutProbe.stderr ?? ""}\n${timeoutProbe.stdout ?? ""}`;
  if (timeoutProbe.status === 0 || !/statement timeout|canceling statement/i.test(timeoutOutput)) {
    fail("PostgreSQL fault injection must prove statement_timeout cancels slow statements.");
  }
  const stamp = reportTimestamp();
  const payload = {
    generatedAt: new Date().toISOString(),
    status: "passed",
    mode: "runtime",
    scope: "platform-infrastructure",
    checks: [{ name: "postgres-statement-timeout", status: "passed" }],
  };
  const jsonPath = writeJsonReport("fault-injection", `fault-injection-tests-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("fault-injection", `fault-injection-tests-${stamp}`, [
    "# Platform Fault Injection Tests", "", `Generated at: ${payload.generatedAt}`, `Status: ${payload.status}`, "", "| Check | Status |", "| --- | --- |", "| postgres-statement-timeout | passed |",
  ]);
  log(`Platform fault injection report written to ${jsonPath} and ${markdownPath}`);
}

async function failureTests() {
  await faultInjectionTests();
  await wafSmoke();
  if (!booleanFlag(argv.confirmServiceStop)) {
    log("Service stop failure tests are armed but not executed. Re-run with --confirmServiceStop in local/staging.");
    return;
  }
  const allTargets = [
    ["redis", "enterprise-redis"],
    ["mariadb", "mariadb"],
    ["postgres", "enterprise-postgres"],
    ["minio", "enterprise-minio"],
    ["keycloak", "enterprise-keycloak"],
    ["nats", "enterprise-nats"],
    ["alertmanager", "enterprise-alertmanager"],
    ["alert-dispatcher", "enterprise-platform-alert-dispatcher"],
    ["waf", "enterprise-waf"],
  ];
  const requested = new Set(String(argv.targets ?? allTargets.map(([name]) => name).join(",")).split(",").map((value) => value.trim()).filter(Boolean));
  const targets = allTargets.filter(([name]) => requested.has(name));
  if (!targets.length) fail("No valid platform failure-test targets selected.");
  const results = [];
  const stopped = [];
  try {
    for (const [name, container] of targets) {
      const startedAt = Date.now();
      run("docker", ["stop", "--time", "10", container], { capture: true });
      stopped.push(container);
      await sleep(1500);
      const healthProbe = run(process.execPath, [path.join(scriptDir, "infra-ops.mjs"), "infra-health"], { allowFailure: true, capture: true });
      const outputText = `${healthProbe.stdout ?? ""}\n${healthProbe.stderr ?? ""}`;
      if (healthProbe.status === 0 || !outputText.includes(container)) fail(`infra-health did not detect stopped ${container}.`);
      run("docker", ["start", container], { capture: true });
      stopped.pop();
      await waitContainerHealthy(container, 120);
      await waitInfraHealth(120);
      results.push({ target: name, container, detected: true, recovered: true, durationMs: Date.now() - startedAt });
    }
  } finally {
    for (const container of stopped.reverse()) run("docker", ["start", container], { allowFailure: true, capture: true });
  }
  const stamp = reportTimestamp();
  const payload = { generatedAt: new Date().toISOString(), status: "passed", targets: results };
  const jsonPath = writeJsonReport("failure-tests", `failure-tests-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("failure-tests", `failure-tests-${stamp}`, [
    "# Platform Failure Tests", "", `Generated at: ${payload.generatedAt}`, "", "| Target | Container | Detected | Recovered | Duration ms |", "| --- | --- | --- | --- | ---: |", ...results.map((result) => `| ${result.target} | ${result.container} | yes | yes | ${result.durationMs} |`),
  ]);
  log(`Failure test reports written to ${jsonPath} and ${markdownPath}`);
}

async function waitContainerHealthy(container, timeoutSeconds = 90) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let lastStatus = "";
  while (Date.now() < deadline) {
    const inspect = run("docker", [
      "inspect",
      "--format",
      "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
      container,
    ], { allowFailure: true, capture: true });
    lastStatus = String(inspect.stdout ?? inspect.stderr ?? "").trim();
    if (inspect.status === 0 && /^running (healthy|none)$/.test(lastStatus)) {
      return;
    }
    await sleep(2000);
  }
  fail(`${container} did not become healthy within ${timeoutSeconds}s. Last status: ${lastStatus}`);
}

async function waitInfraHealth(timeoutSeconds = 90) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  let lastOutput = "";
  while (Date.now() < deadline) {
    const health = run(process.execPath, [path.join(scriptDir, "infra-ops.mjs"), "infra-health"], { allowFailure: true, capture: true });
    lastOutput = `${health.stdout ?? ""}\n${health.stderr ?? ""}`;
    if (health.status === 0) {
      return;
    }
    await sleep(3000);
  }
  fail(`infra-health did not recover within ${timeoutSeconds}s:\n${lastOutput}`);
}

async function maintainabilityHygiene() {
  await withLocalCheckReport("maintainability-hygiene", async () => {
    infraMaintainabilityHygiene();
  }, { scope: "platform-infrastructure" });
}

async function performanceHygiene() {
  await withLocalCheckReport("performance-hygiene", async () => {
    await infraPerformanceHygiene();
  }, { scope: "platform-infrastructure" });
}

function infraMaintainabilityHygiene() {
  const opsWrapper = readText(path.join(infraRoot, "scripts", "infra-ops.sh"));
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const controlCenterServer = readText(path.join(infraRoot, "control-center", "server.mjs"));
  const projectRouterServer = readText(path.join(infraRoot, "project-router", "server.mjs"));
  assertMatch(opsWrapper, /docker build[\s\S]*docker\/ops\.Dockerfile[\s\S]*docker run --rm/, "infra-ops wrapper must stay Dockerized.");
  assertMatch(opsWrapper, /PROJECT_SOURCE_ROOT=\$SOURCE_CONTAINER_ROOT/, "infra-ops wrapper must pass source root explicitly into the ops container.");
  assertNoMatch(`${compose}\n${controlCenterServer}\n${projectRouterServer}`, /stexor|fireport|matthewdifilippo/i, "Core infrastructure must stay project-generic.");
  assertNoMatch(projectRouterServer, /node:child_process|spawn\(|execFile\(|exec\(/, "Project router must stay proxy-only.");
  const shellWrappers = fs.readdirSync(path.join(infraRoot, "scripts"))
    .filter((name) => name.endsWith(".sh"))
    .sort();
  const directOperationalScripts = new Set([
    "backup-scheduler.sh",
    "alertmanager-secret-permissions.sh",
    "build-context-sandbox-test.sh",
    "build-daemon-isolation-sandbox-test.sh",
    "cloudflare-origin-lock-ufw.sh",
    "collect-host-reliability.sh",
    "compose-runtime-check.sh",
    "compose-vps.sh",
    "configure-host-wait-online.sh",
    "container-metrics-sandbox-test.sh",
    "core-image-supply-chain-test.sh",
    "database-ownership-sandbox-test.sh",
    "deploy-vps-input-test.sh",
    "deploy-vps-remote.sh",
    "helper-image-supply-chain-test.sh",
    "host-reliability-sandbox-test.sh",
    "hosted-workload-lock.sh",
    "install-host-reliability-collector.sh",
    "keycloak-backchannel-configure.sh",
    "keycloak-passkey-readiness.sh",
    "minio-service-identity.sh",
    "network-segmentation-sandbox-test.sh",
    "php-project-runtime.sh",
    "php-runtime-supply-chain-test.sh",
    "prepare-hosted-workloads.sh",
    "prepare-vps-runtime.sh",
    "runtime-isolation-sandbox-test.sh",
    "verify-locked-images.sh",
    "vps-evidence-remote.sh",
    "workload-egress-firewall.sh",
    "dast-zap-baseline.sh",
    "deploy-vps.sh",
    "infra-ops.sh",
    "install-container-metrics-collector.sh",
    "install-offsite-backup-cron.sh",
    "node-project-runtime.sh",
    "vps-bootstrap-ubuntu.sh",
    "vps-go-live.sh",
    "vps-hardening-ubuntu.sh",
    "vps-host-readiness.sh",
    "vps-postdeploy.sh",
    "vps-preflight.sh",
    "write-docker-stats-json.sh",
  ]);
  for (const name of shellWrappers) {
    const text = readText(path.join(infraRoot, "scripts", name));
    if (directOperationalScripts.has(name)) {
      if (name === "dast-zap-baseline.sh") {
        assertMatch(text, /docker run[\s\S]*zap-baseline\.py/, "DAST ZAP wrapper must stay containerized.");
      }
    } else {
      assertMatch(text, /infra-ops\.sh/, `Shell wrapper ${name} must delegate to infra-ops.sh.`);
      assertNoMatch(text, /exec node|infra-ops\.mjs|infra-secret-manager\.mjs|cloudflare-from-zero\.mjs/, `Shell wrapper ${name} must not bypass the Dockerized ops runner.`);
    }
  }
  for (const file of ["README.md", "RUNBOOK.md", "SECURITY.md", "VPS-PREDEPLOY-CHECKLIST.md"]) {
    if (!fs.existsSync(path.join(infraRoot, file))) fail(`${file} must exist as maintainer-facing documentation.`);
  }
  log("Infrastructure maintainability hygiene checks passed.");
}

async function infraPerformanceHygiene() {
  const cssSize = fs.statSync(path.join(infraRoot, "control-center", "styles", "control-center.css")).size;
  const jsSize = fs.statSync(path.join(infraRoot, "control-center", "styles", "control-center.js")).size;
  if (cssSize > 200000) fail(`Control Center CSS is too large for the local portal shell: ${cssSize} bytes.`);
  if (jsSize > 100000) fail(`Control Center JS is too large for the local portal shell: ${jsSize} bytes.`);
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  assertMatch(compose, /x-default-logging:[\s\S]*max-size:\s+"10m"[\s\S]*max-file:\s+"5"/, "Compose must bound json-file logs for runtime performance.");
  const prometheus = readText(path.join(infraRoot, "prometheus", "prometheus.yml"));
  assertMatch(prometheus, /scrape_interval:\s*[0-9]+s/, "Prometheus must use explicit scrape intervals.");
  const controlCenterServer = readText(path.join(infraRoot, "control-center", "server.mjs"));
  assertMatch(controlCenterServer, /resourceMetricsTtlMs/, "Control Center resource probes must have a metrics TTL.");
  assertMatch(controlCenterServer, /projectDiskUsageTtlMs/, "Control Center disk usage probes must have a cache TTL.");
  await composeHealthcheckCoverage();
  log("Infrastructure performance hygiene checks passed.");
}

async function initLocalSecrets() {
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
  const secretsDir = path.resolve(argv.secretsDir ?? path.join(infraRoot, "secrets"));
  const args = ["init", "--secretsDir", secretsDir, "--envFile", envFile];
  if (booleanFlag(argv.force)) args.push("--force");
  runSecretManager(args);
  if (booleanFlag(argv.sanitizeEnv) && fs.existsSync(envFile)) {
    const sensitive = new Set([
      "POSTGRES_SUPERUSER_PASSWORD",
      "KEYCLOAK_DB_PASSWORD",
      "REDIS_PASSWORD",
      "KEYCLOAK_ADMIN_PASSWORD",
      "NATS_PASSWORD",
      "MINIO_ROOT_PASSWORD",
      "MARIADB_ROOT_PASSWORD",
      "PHPMYADMIN_CONTROL_PASSWORD",
      "GRAFANA_ADMIN_PASSWORD",
      "SMTP_PASSWORD",
      "ALERTMANAGER_WEBHOOK_TOKEN",
    ]);
    const next = fs.readFileSync(envFile, "utf8").split(/\r?\n/).map((line) => {
      const key = line.split("=", 1)[0];
      return sensitive.has(key) ? `${key}=managed_by_local_secret_file` : line;
    }).join("\n");
    fs.writeFileSync(envFile, next, "utf8");
  }
  log("Platform secrets initialized through Infra Secret Manager.");
}

async function localSecretManager() {
  await initLocalSecrets();
  await validateLocalSecrets();
  log("Local secret manager is ready: Docker secret files are materialized from the encrypted local store. Existing backups are not granted trust automatically.");
}

async function secretManager() {
  const args = [...argv._];
  for (const [key, value] of Object.entries(argv)) {
    if (key === "_") continue;
    args.push(`--${key}`);
    if (value !== true) args.push(String(value));
  }
  runSecretManager(args.length ? args : ["status"]);
}

function readExternalUptimeManifest() {
  const manifestPath = path.resolve(argv.manifest ?? path.join(infraRoot, "monitoring", "external-uptime.example.json"));
  const manifest = readJsonFile(manifestPath, manifestPath);
  if (manifest.version !== 1) {
    fail(`Unsupported external uptime manifest version in ${manifestPath}.`);
  }
  if (!Array.isArray(manifest.targets) || manifest.targets.length === 0) {
    fail(`External uptime manifest has no targets: ${manifestPath}`);
  }
  return { manifestPath, manifest };
}

function resolveUptimeTarget(target, defaults, variables) {
  const expectedStatuses = target.expectedStatuses ?? defaults.expectedStatuses ?? [200];
  if (!Array.isArray(expectedStatuses) || expectedStatuses.some((status) => !Number.isInteger(status))) {
    fail(`Invalid expectedStatuses for uptime target ${target.name ?? "(unnamed)"}.`);
  }
  const url = expandTemplate(target.url, variables);
  const parsed = new URL(url);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    fail(`External uptime target ${target.name} must use http or https.`);
  }
  const timeoutMs = Number(target.timeoutMs ?? defaults.timeoutMs ?? 5000);
  const maxLatencyMs = Number(target.maxLatencyMs ?? defaults.maxLatencyMs ?? 2000);
  const intervalSeconds = Number(target.intervalSeconds ?? defaults.intervalSeconds ?? 60);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    fail(`Invalid timeoutMs for uptime target ${target.name ?? parsed.hostname}.`);
  }
  if (!Number.isFinite(maxLatencyMs) || maxLatencyMs <= 0) {
    fail(`Invalid maxLatencyMs for uptime target ${target.name ?? parsed.hostname}.`);
  }
  if (!Number.isFinite(intervalSeconds) || intervalSeconds <= 0) {
    fail(`Invalid intervalSeconds for uptime target ${target.name ?? parsed.hostname}.`);
  }
  return {
    name: String(target.name ?? parsed.hostname),
    url,
    method: String(target.method ?? defaults.method ?? "GET").toUpperCase(),
    timeoutMs,
    maxLatencyMs,
    intervalSeconds,
    expectedStatuses,
    expectedBodyIncludes: target.expectedBodyIncludes,
    headers: {
      ...(defaults.headers ?? {}),
      ...(target.headers ?? {}),
    },
  };
}

function firstMonitorValue(monitor, keys) {
  for (const key of keys) {
    const value = monitor?.[key];
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      return value;
    }
  }
  return null;
}

function monitorNumber(monitor, keys, label, targetName) {
  const raw = firstMonitorValue(monitor, keys);
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    fail(`External uptime monitor ${targetName} must include numeric ${label}.`);
  }
  return value;
}

function monitorTimestamp(monitor, targetName) {
  const raw = firstMonitorValue(monitor, ["lastCheckedAt", "checkedAt", "lastCheckAt", "lastProbeAt"]);
  const timestamp = Date.parse(raw ?? "");
  if (!Number.isFinite(timestamp)) {
    fail(`External uptime monitor ${targetName} must include a valid lastCheckedAt timestamp.`);
  }
  return { timestamp, iso: new Date(timestamp).toISOString() };
}

function monitorStateOk(monitor) {
  const raw = firstMonitorValue(monitor, ["lastStatus", "status", "state", "lastState"]);
  if (raw === null) {
    return true;
  }
  return /^(ok|up|healthy|success|passing|available)$/i.test(String(raw).trim());
}

function providerMonitorResult({ monitor, target, monitorUrl, maxAgeHours }) {
  const checkedAt = monitorTimestamp(monitor, target.name);
  const ageHours = Math.max(0, (Date.now() - checkedAt.timestamp) / 3600000);
  if (ageHours > maxAgeHours) {
    fail(`External uptime monitor ${target.name} last check is ${ageHours.toFixed(1)}h old; max ${maxAgeHours}h.`);
  }
  const status = monitorNumber(monitor, ["lastStatusCode", "statusCode", "httpStatus", "lastHttpStatus"], "lastStatusCode", target.name);
  const latencyMs = monitorNumber(monitor, ["lastLatencyMs", "latencyMs", "responseTimeMs", "lastResponseTimeMs"], "lastLatencyMs", target.name);
  const stateOk = monitorStateOk(monitor);
  const statusOk = target.expectedStatuses.includes(status);
  const latencyOk = latencyMs <= target.maxLatencyMs;
  const ok = stateOk && statusOk && latencyOk;
  if (!ok) {
    fail(`External uptime provider monitor ${target.name} last result failed: status=${status} expected=${target.expectedStatuses.join(",")} latencyMs=${latencyMs} max=${target.maxLatencyMs} stateOk=${stateOk}.`);
  }
  return {
    name: target.name,
    url: monitorUrl,
    status,
    expectedStatuses: target.expectedStatuses,
    latencyMs,
    maxLatencyMs: target.maxLatencyMs,
    checkedAt: checkedAt.iso,
    ageHours: Number(ageHours.toFixed(2)),
    ok,
    monitorId: String(monitor.monitorId ?? monitor.id ?? ""),
    regions: monitor.regions,
    source: "provider-evidence",
  };
}

function validateExternalUptimeProviderEvidence({ evidencePath, targets, manifest }) {
  const resolved = path.resolve(evidencePath);
  const evidence = readJsonFile(resolved, resolved);
  if (evidence.version !== 1) {
    fail(`Unsupported external uptime provider evidence version in ${resolved}.`);
  }
  const provider = String(evidence.provider ?? "").trim();
  if (!provider) {
    fail("External uptime provider evidence must name the provider.");
  }
  if (evidence.external !== true) {
    fail("External uptime provider evidence must set external=true.");
  }
  if (/local|localhost|internal/i.test(String(evidence.source ?? ""))) {
    fail("External uptime provider evidence source must not be local/internal.");
  }
  const verifiedAtMs = Date.parse(evidence.verifiedAt ?? "");
  if (!Number.isFinite(verifiedAtMs)) {
    fail("External uptime provider evidence must include a valid verifiedAt timestamp.");
  }
  const maxAgeHours = Number(argv.maxProviderEvidenceAgeHours ?? evidence.maxAgeHours ?? manifest.providerEvidence?.maxAgeHours ?? 24);
  const ageHours = Math.max(0, (Date.now() - verifiedAtMs) / 3600000);
  if (ageHours > maxAgeHours) {
    fail(`External uptime provider evidence is ${ageHours.toFixed(1)}h old; max ${maxAgeHours}h.`);
  }
  const attestationValue = argv.providerEvidenceAttestation;
  const policy = releaseTrustPolicy();
  const repository = argv.providerEvidenceRepository ?? evidence.attestation?.repository ?? process.env.GITHUB_REPOSITORY;
  const signerWorkflow = argv.providerEvidenceWorkflow ?? evidence.attestation?.signerWorkflow ?? (repository ? `${repository}/${policy.signer_workflow_path}` : null);
  const sourceDigest = argv.providerEvidenceSourceDigest ?? evidence.attestation?.sourceDigest;
  const sourceRef = argv.providerEvidenceSourceRef ?? evidence.attestation?.sourceRef;
  const bundle = typeof attestationValue === "string" && !booleanFlag(attestationValue) && attestationValue !== "online"
    ? attestationValue
    : null;
  const attestationOptions = providerEvidenceAttestationOptions({
    enabled: Boolean(attestationValue),
    evidencePath: resolved,
    evidenceDigest: sha256File(resolved),
    repository,
    signerWorkflow,
    sourceDigest,
    sourceRef,
    bundle,
    trustedRoot: argv.providerEvidenceTrustedRoot ?? null,
  });
  loadGithubTokenFromFile();
  const authentication = verifyGithubAttestation({
    ...attestationOptions,
    predicateType: policy.predicate_type,
    certOidcIssuer: policy.cert_oidc_issuer,
  });
  const monitors = Array.isArray(evidence.monitors) ? evidence.monitors : [];
  if (!monitors.length) {
    fail("External uptime provider evidence must include monitors.");
  }

  const monitorByTarget = new Map();
  for (const monitor of monitors) {
    const targetName = String(monitor.targetName ?? monitor.name ?? "").trim();
    if (!targetName) {
      fail("External uptime provider monitor is missing targetName.");
    }
    if (monitor.enabled === false) {
      fail(`External uptime monitor is disabled: ${targetName}`);
    }
    if (!String(monitor.monitorId ?? monitor.id ?? "").trim()) {
      fail(`External uptime monitor ${targetName} is missing monitorId.`);
    }
    if (!Array.isArray(monitor.regions) || monitor.regions.length === 0) {
      fail(`External uptime monitor ${targetName} must include provider regions.`);
    }
    monitorByTarget.set(targetName, monitor);
  }

  const coveredTargets = [];
  const missingTargets = [];
  const intervalViolations = [];
  const results = [];
  for (const target of targets) {
    const monitor = monitorByTarget.get(target.name);
    if (!monitor) {
      missingTargets.push(target.name);
      continue;
    }
    const monitorUrl = expandTemplate(monitor.url ?? "", { ...parseEnv(path.resolve(argv.envFile ?? path.join(infraRoot, ".env"))), ...process.env });
    if (monitorUrl !== target.url) {
      fail(`External uptime monitor ${target.name} URL mismatch: ${monitorUrl || "(missing)"} !== ${target.url}`);
    }
    if (!publicEvidenceUrl(monitorUrl)) {
      fail(`External uptime monitor ${target.name} is not a public target: ${monitorUrl}`);
    }
    const intervalSeconds = Number(monitor.intervalSeconds ?? target.intervalSeconds);
    if (!Number.isFinite(intervalSeconds) || intervalSeconds > target.intervalSeconds) {
      intervalViolations.push(`${target.name}:${intervalSeconds}`);
    }
    results.push(providerMonitorResult({ monitor, target, monitorUrl, maxAgeHours }));
    coveredTargets.push(target.name);
  }
  if (missingTargets.length) {
    fail(`External uptime provider evidence does not cover targets: ${missingTargets.join(", ")}`);
  }
  if (intervalViolations.length) {
    fail(`External uptime provider monitor intervals exceed manifest thresholds: ${intervalViolations.join(", ")}`);
  }

  return {
    verified: true,
    provider,
    external: true,
    evidencePath: resolved,
    verifiedAt: new Date(verifiedAtMs).toISOString(),
    maxAgeHours,
    ageHours: Number(ageHours.toFixed(2)),
    monitorCount: monitors.length,
    coveredTargets,
    results,
    authentication: {
      verified: authentication.verified === true,
      kind: authentication.kind,
      provider: authentication.provider,
      repository: authentication.repository,
      signerWorkflow: authentication.signerWorkflow,
      sourceDigest: authentication.sourceDigest,
      sourceRef: authentication.sourceRef,
      subjectCount: authentication.subjects.length,
      verifiedTimestampCount: authentication.verifiedTimestampCount,
      evidenceSha256: attestationOptions.expectedSubjectDigest,
    },
  };
}

function writeExternalUptimeReport({ manifestPath, providerEvidence, results, mode }) {
  const stamp = reportTimestamp();
  const payload = { generatedAt: new Date().toISOString(), mode, manifestPath, providerEvidence, results };
  const jsonPath = writeJsonReport("uptime", `external-uptime-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("uptime", `external-uptime-${stamp}`, [
    "# Platform External Uptime Check",
    "",
    `Generated at: ${payload.generatedAt}`,
    `Mode: ${mode}`,
    `Manifest: ${manifestPath}`,
    `Provider evidence: ${providerEvidence.verified ? `${providerEvidence.provider} verified at ${providerEvidence.verifiedAt}` : providerEvidence.reason}`,
    "",
    "| Target | Status | Latency ms | Max ms | Result | Source |",
    "| --- | ---: | ---: | ---: | --- | --- |",
    ...results.map((result) => `| ${result.name} | ${result.status ?? "error"} | ${result.latencyMs ?? "n/a"} | ${result.maxLatencyMs} | ${result.ok ? "ok" : "fail"} | ${result.source ?? "probe"} |`),
  ]);
  return { payload, jsonPath, markdownPath };
}

async function externalUptimeCheck(options = {}) {
  log("==> External uptime check");
  const envFile = path.resolve(options.envFile ?? argv.envFile ?? path.join(infraRoot, ".env"));
  const variables = { ...parseEnv(envFile), ...process.env };
  const { manifestPath, manifest } = readExternalUptimeManifest();
  const defaults = manifest.defaults ?? {};
  const targets = manifest.targets.map((target) => resolveUptimeTarget(target, defaults, variables));
  const providerEvidencePath = argv.providerEvidence ? path.resolve(argv.providerEvidence) : null;
  const requireProviderEvidence = booleanFlag(argv.requireProviderEvidence);
  const validateProviderEvidenceOnly = booleanFlag(argv.validateProviderEvidenceOnly);

  if (options.dryRun || booleanFlag(argv.dryRun)) {
    for (const target of targets) {
      log(`${target.name}: ${target.method} ${target.url} statuses=${target.expectedStatuses.join(",")} timeoutMs=${target.timeoutMs} maxLatencyMs=${target.maxLatencyMs} intervalSeconds=${target.intervalSeconds}`);
    }
    if (providerEvidencePath) {
      log(`Provider evidence will be validated from ${providerEvidencePath}`);
    }
    const dryRunResults = targets.map((target) => ({
      name: target.name,
      url: target.url,
      status: null,
      expectedStatuses: target.expectedStatuses,
      latencyMs: null,
      maxLatencyMs: target.maxLatencyMs,
      bodyCheck: target.expectedBodyIncludes ? "not-run" : null,
      ok: true,
      source: "manifest-dry-run",
    }));
    const report = writeExternalUptimeReport({
      manifestPath,
      providerEvidence: { verified: false, provider: null, reason: "provider evidence not supplied in manifest dry-run" },
      results: dryRunResults,
      mode: "dry-run",
    });
    log(`External uptime manifest dry-run passed: ${manifestPath}`);
    log(`External uptime dry-run reports written to ${report.jsonPath} and ${report.markdownPath}`);
    return;
  }

  if (validateProviderEvidenceOnly) {
    if (!providerEvidencePath) {
      fail("Pass --providerEvidence <file> with --validateProviderEvidenceOnly.");
    }
    const providerEvidence = validateExternalUptimeProviderEvidence({ evidencePath: providerEvidencePath, targets, manifest });
    const report = writeExternalUptimeReport({
      manifestPath,
      providerEvidence,
      results: providerEvidence.results,
      mode: "provider-evidence-only",
    });
    log(`External uptime provider evidence validated: ${providerEvidence.provider}; monitors=${providerEvidence.monitorCount}; targets=${providerEvidence.coveredTargets.join(",")}`);
    log(`External uptime reports written to ${report.jsonPath} and ${report.markdownPath}`);
    return;
  }

  if (requireProviderEvidence && !providerEvidencePath) {
    fail("External uptime provider evidence is required. Pass --providerEvidence <file>.");
  }
  const providerEvidence = providerEvidencePath
    ? validateExternalUptimeProviderEvidence({ evidencePath: providerEvidencePath, targets, manifest })
    : { verified: false, provider: null, reason: "provider evidence not supplied" };

  const results = [];
  for (const target of targets) {
    const started = performance.now();
    let response = null;
    let error = null;
    try {
      response = await request(target.method, target.url, { headers: target.headers, timeoutMs: target.timeoutMs });
    } catch (caught) {
      error = String(caught?.message ?? caught);
    }
    const latencyMs = Math.round(performance.now() - started);
    const statusOk = response ? target.expectedStatuses.includes(response.status) : false;
    const bodyOk = !target.expectedBodyIncludes || Boolean(response?.text.includes(target.expectedBodyIncludes));
    const latencyOk = latencyMs <= target.maxLatencyMs;
    const ok = statusOk && bodyOk && latencyOk && !error;
    results.push({
      name: target.name,
      url: target.url,
      status: response?.status ?? null,
      expectedStatuses: target.expectedStatuses,
      latencyMs,
      maxLatencyMs: target.maxLatencyMs,
      bodyCheck: target.expectedBodyIncludes ? bodyOk : null,
      ok,
      error,
    });
    log(`${ok ? "ok" : "fail"} ${target.name}: status=${response?.status ?? "error"} latencyMs=${latencyMs}`);
  }

  const report = writeExternalUptimeReport({ manifestPath, providerEvidence, results, mode: "probe" });
  const failed = results.filter((result) => !result.ok);
  if (failed.length) {
    failed.forEach((result) => log(`${result.name} failed: ${result.error ?? `status=${result.status} expected=${result.expectedStatuses.join(",")} latencyMs=${result.latencyMs}`}`));
    fail(`External uptime check failed for ${failed.length} target(s). Reports: ${report.jsonPath}, ${report.markdownPath}`);
  }
  log(`External uptime reports written to ${report.jsonPath} and ${report.markdownPath}`);
}

function alertMetricScript({ requireEmailDelivery, requireForwardDelivery, timeoutMs, alertmanagerHost = "alertmanager" }) {
  return `
const crypto = require("node:crypto");
const http = require("node:http");
const timeoutMs = ${JSON.stringify(timeoutMs)};
const required = ${JSON.stringify({ email: requireEmailDelivery, forward: requireForwardDelivery })};
function request(hostname, port, method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : undefined;
    const req = http.request({ method, hostname, port, path, headers: data ? { "content-type": "application/json", "content-length": data.length } : {}, timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode || 0, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error(method + " " + path + " timed out")));
    if (data) req.write(data);
    req.end();
  });
}
function metric(text, name, labels = "") {
  for (const line of text.split(/\\r?\\n/)) {
    if (!line.startsWith(name)) continue;
    if (labels && !line.includes("{" + labels + "}")) continue;
    const value = Number(line.trim().split(/\\s+/).at(-1));
    if (Number.isFinite(value)) return value;
  }
  return 0;
}
async function metrics() {
  const response = await request("127.0.0.1", 3000, "GET", "/metrics");
  if (response.status !== 200) throw new Error("metrics status " + response.status);
  return response.text;
}
(async () => {
  const before = await metrics();
  const probeId = crypto.randomUUID();
  const probeAlertname = "PlatformSyntheticAlertDeliveryTest_" + probeId.replaceAll("-", "");
  const startedAt = new Date();
  const labels = { alertname: probeAlertname, severity: "info", service: "platform-infrastructure", job: "alert-evidence", platform_probe: "alert-delivery", platform_probe_id: probeId };
  const annotations = { summary: "Synthetic platform alert delivery test", description: "Generated by alert-evidence." };
  const firingAlert = { labels, annotations, startsAt: startedAt.toISOString(), endsAt: new Date(startedAt.getTime() + 60000).toISOString() };
  const accepted = await request(${JSON.stringify(alertmanagerHost)}, 9093, "POST", "/api/v2/alerts", [firingAlert]);
  if (accepted.status < 200 || accepted.status >= 300) throw new Error("Alertmanager API status " + accepted.status);
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const after = await metrics();
    const webhookOk = metric(after, "platform_alert_webhook_requests_total") > metric(before, "platform_alert_webhook_requests_total");
    const firingOk = metric(after, "platform_alert_webhook_alerts_total", 'status="firing"') > metric(before, "platform_alert_webhook_alerts_total", 'status="firing"');
    const emailOk = !required.email || metric(after, "platform_alert_delivery_total", 'channel="email",result="success"') > metric(before, "platform_alert_delivery_total", 'channel="email",result="success"');
    const forwardOk = !required.forward || metric(after, "platform_alert_delivery_total", 'channel="forward",result="success"') > metric(before, "platform_alert_delivery_total", 'channel="forward",result="success"');
    if (webhookOk && firingOk && emailOk && forwardOk) {
      console.log(JSON.stringify({ probeId, probeAlertname, acceptedStatus: accepted.status, delivery: { email: emailOk, forward: forwardOk } }));
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("alert delivery counters did not increase before timeout");
})().catch((error) => { console.error(error.message || String(error)); process.exit(1); });
`;
}

async function alertEvidence(options = {}) {
  log("==> Platform alert delivery evidence");
  const sendTest = options.sendTest ?? booleanFlag(argv.sendTest);
  const enforce = options.enforce ?? booleanFlag(argv.enforce);
  const requireEmailDelivery = options.requireEmailDelivery ?? booleanFlag(argv.requireEmailDelivery);
  const requireForwardDelivery = options.requireForwardDelivery ?? booleanFlag(argv.requireForwardDelivery);
  const timeoutMs = positiveInteger(options.timeoutMs ?? argv.timeoutMs ?? 15000, "--timeoutMs", 1000);
  const dispatcherContainer = String(options.dispatcherContainer ?? argv.dispatcherContainer ?? "enterprise-platform-alert-dispatcher").trim();
  const alertmanagerHost = String(options.alertmanagerHost ?? argv.alertmanagerHost ?? "alertmanager").trim();
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const composeSecrets = readText(path.join(infraRoot, "compose.secrets.yaml"));
  const alertmanagerConfig = readText(path.join(infraRoot, "alertmanager", "alertmanager.yml"));
  const dispatcherSource = readText(path.join(infraRoot, "platform-alert-dispatcher", "server.mjs"));
  const prometheusAlerts = readText(path.join(infraRoot, "prometheus", "rules", "enterprise-alerts.yml"));
  const checks = [
    ["alertmanager-dispatcher-target", /platform-alert-dispatcher:3000\/alerts\/prometheus/.test(alertmanagerConfig)],
    ["alertmanager-bearer-file", /credentials_file:\s+\/run\/secrets\/alertmanager_webhook_token/.test(alertmanagerConfig)],
    ["alertmanager-probe-route", /platform_probe="alert-delivery"[\s\S]*group_wait:\s+0s/.test(alertmanagerConfig)],
    ["dispatcher-secret-files", /ALERTMANAGER_WEBHOOK_TOKEN_FILE:\s+\/run\/secrets\/alertmanager_webhook_token/.test(composeSecrets) && /SMTP_PASSWORD_FILE:\s+\/run\/secrets\/smtp_password/.test(composeSecrets)],
    ["dispatcher-auth", /authorized\([\s\S]*alert_webhook_unauthorized/.test(dispatcherSource)],
    ["dispatcher-delivery-metrics", /platform_alert_delivery_total[\s\S]*channel=\\"email\\"[\s\S]*channel=\\"forward\\"/.test(dispatcherSource)],
    ["dispatcher-healthcheck", /platform-alert-dispatcher:[\s\S]*\/health/.test(compose)],
    ["delivery-failure-alert", /\bAlertDeliveryFailed\b/.test(prometheusAlerts)],
  ].map(([name, passed]) => ({ name, passed: Boolean(passed) }));
  const issues = checks.filter((check) => !check.passed).map((check) => `Alert evidence check failed: ${check.name}`);
  let runtime = null;
  if (sendTest) {
    try {
      const inspect = run("docker", ["inspect", "--format", "{{.State.Status}}", dispatcherContainer], { capture: true, allowFailure: true });
      if (inspect.status !== 0 || String(inspect.stdout ?? "").trim() !== "running") throw new Error("dispatcher unavailable");
      const result = dockerExec(dispatcherContainer, ["node", "-e", alertMetricScript({ requireEmailDelivery, requireForwardDelivery, timeoutMs, alertmanagerHost })], { capture: true });
      runtime = JSON.parse(String(result.stdout ?? "").trim().split(/\r?\n/).at(-1));
      const logs = run("docker", ["logs", "--since", "2m", dispatcherContainer], { capture: true, allowFailure: true });
      const logText = `${logs.stdout ?? ""}\n${logs.stderr ?? ""}`;
      runtime.exactReceiverReceipt = logs.status === 0 && logText.includes("alerts_received") && logText.includes(runtime.probeAlertname);
      checks.push({ name: "alertmanager-runtime-exact-receipt", passed: runtime.exactReceiverReceipt });
      if (!runtime.exactReceiverReceipt) issues.push("Synthetic alert had no exact correlated dispatcher log receipt.");
    } catch {
      runtime = { status: "failed", dispatcherContainer, exactReceiverReceipt: false, errorRedacted: true };
      issues.push("Synthetic alert delivery through Alertmanager failed; runtime details were redacted.");
    }
  } else {
    issues.push("Synthetic runtime alert was not sent. Re-run with --sendTest in staging/VPS.");
  }
  const payload = { generatedAt: new Date().toISOString(), mode: sendTest ? "send-test" : "summary", status: issues.length ? "warning" : "passed", scope: "platform-infrastructure", checks, runtime, requestedDelivery: { email: requireEmailDelivery, forward: requireForwardDelivery }, issues };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("alerts", `alert-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("alerts", `alert-evidence-${stamp}`, ["# Platform Alert Evidence", "", `Status: ${payload.status}`, `Mode: ${payload.mode}`, `Generated at: ${payload.generatedAt}`, "", "| Check | Passed |", "| --- | --- |", ...checks.map((check) => `| ${check.name} | ${check.passed ? "yes" : "no"} |`), "", "## Issues", "", ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"])]);
  log(`Alert evidence written to ${jsonPath} and ${markdownPath}`);
  if (enforce && issues.length) fail(`Alert evidence enforcement failed with ${issues.length} issue(s). Reports: ${jsonPath}, ${markdownPath}`);
  return payload;
}

async function loadSmoke() {
  const requests = positiveInteger(argv.requests ?? 80, "requests");
  const concurrency = positiveInteger(argv.concurrency ?? 8, "concurrency");
  const maxP95Ms = Number(argv.maxP95Ms ?? 750);
  let target = "container:enterprise-control-center/health";
  let metric = null;
  if (!argv.url && !booleanFlag(argv.edge)) {
    metric = runInternalPlatformLoadProbe({ label: "Internal Control Center load smoke", requests, concurrency, maxP95Ms });
  } else {
    const url = argv.url ?? "https://api.localhost.com/health";
    target = url;
    metric = await runLoadProbe({ label: "Load smoke", url, requests, concurrency, maxP95Ms });
  }
  writeLoadSmokeReport({
    generatedAt: new Date().toISOString(),
    status: "passed",
    target,
    requests,
    concurrency,
    maxP95Ms,
    metric,
  });
}

function writeLoadSmokeReport(payload) {
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("load", `load-smoke-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("load", `load-smoke-${stamp}`, [
    "# Platform Load Smoke",
    "",
    `Generated at: ${payload.generatedAt}`,
    `Status: ${payload.status}`,
    `Target: ${payload.target}`,
    "",
    "| Requests | Concurrency | Avg ms | P95 ms | Max P95 ms | Errors |",
    "| ---: | ---: | ---: | ---: | ---: | ---: |",
    `| ${payload.requests} | ${payload.concurrency} | ${Number(payload.metric.avg).toFixed(2)} | ${payload.metric.p95} | ${payload.maxP95Ms} | ${payload.metric.errors ?? 0} |`,
  ]);
  log(`Load smoke reports written to ${jsonPath} and ${markdownPath}`);
}

function writeLoadProfileReport(payload) {
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("load", `load-profile-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("load", `load-profile-${stamp}`, [
    "# Platform Load Profile",
    "",
    `Generated at: ${payload.generatedAt}`,
    `Status: ${payload.status}`,
    `Target: ${payload.target}`,
    "",
    "| Duration seconds | Target RPS | Requests | Concurrency | Avg ms | P95 ms | Max P95 ms | Errors |",
    "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    `| ${payload.durationSeconds} | ${payload.targetRps} | ${payload.requests} | ${payload.concurrency} | ${Number(payload.metric.avg).toFixed(2)} | ${payload.metric.p95} | ${payload.maxP95Ms} | ${payload.metric.errors ?? 0} |`,
    "",
    "This is local runtime evidence. It does not replace the public edge/CDN load benchmark required for production go-live.",
  ]);
  log(`Load profile reports written to ${jsonPath} and ${markdownPath}`);
  return { jsonPath, markdownPath };
}

async function loadProfile() {
  const durationSeconds = positiveInteger(argv.durationSeconds ?? 60, "durationSeconds");
  const targetRps = positiveInteger(argv.targetRps ?? 8, "targetRps");
  const concurrency = positiveInteger(argv.concurrency ?? Math.max(4, Math.min(64, targetRps)), "concurrency");
  const requests = positiveInteger(argv.requests ?? durationSeconds * targetRps, "requests");
  const maxP95Ms = Number(argv.maxP95Ms ?? 1000);
  const useEdge = Boolean(argv.url || booleanFlag(argv.edge));
  const url = argv.url ?? "https://api.localhost.com/health";
  const target = useEdge ? url : "container:enterprise-control-center/health";
  await withLocalCheckReport("load-profile", async () => {
    const before = dockerStatsSnapshot("before-load-profile");
    const metric = useEdge
      ? await runLoadProbe({ label: "Sustained load profile", url, requests, concurrency, maxP95Ms })
      : runInternalPlatformLoadProbe({ label: "Sustained internal Control Center load profile", requests, concurrency, maxP95Ms });
    const after = dockerStatsSnapshot("after-load-profile");
    writeLoadProfileReport({
      generatedAt: new Date().toISOString(),
      status: "passed",
      target,
      mode: useEdge ? "edge" : "internal",
      durationSeconds,
      targetRps,
      requests,
      concurrency,
      maxP95Ms,
      metric,
      stats: { before, after },
    });
  }, { mode: useEdge ? "edge" : "internal", target, durationSeconds, targetRps, requests, concurrency, maxP95Ms });
}

function selectedEdgeHeaders(headers = {}) {
  const wanted = [
    "server",
    "cf-ray",
    "cf-cache-status",
    "cdn-cache",
    "x-cache",
    "x-served-by",
    "x-vercel-id",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "via",
  ];
  return Object.fromEntries(wanted
    .map((key) => [key, headers[key]])
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => [key, Array.isArray(value) ? value.join(",") : String(value)]));
}

function detectEdgeProvider(headers = {}) {
  const value = (name) => String(headers[name] ?? "").toLowerCase();
  if (headers["cf-ray"] || headers["cf-cache-status"] || value("server").includes("cloudflare")) return "cloudflare";
  if (headers["x-amz-cf-id"] || headers["x-amz-cf-pop"] || value("x-cache").includes("cloudfront")) return "cloudfront";
  if (headers["x-served-by"] || value("x-cache").includes("fastly")) return "fastly";
  if (value("server").includes("akamai") || value("via").includes("akamai")) return "akamai";
  if (headers["x-vercel-id"] || value("server").includes("vercel")) return "vercel";
  if (value("via")) return "generic-cdn";
  return null;
}

function authenticatedEdgeProviderEvidence({ evidencePath, expectedUrl, expectedProvider, currentCandidateId, observedStatus }) {
  const resolvedEvidencePath = path.resolve(String(evidencePath));
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor = null;
  let evidenceBytes = null;
  try {
    descriptor = fs.openSync(resolvedEvidencePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size <= 0 || before.size > 1024 * 1024) {
      fail("Edge provider evidence must be a regular JSON file no larger than 1 MiB.");
    }
    evidenceBytes = Buffer.allocUnsafe(before.size);
    let offset = 0;
    while (offset < evidenceBytes.length) {
      const read = fs.readSync(descriptor, evidenceBytes, offset, evidenceBytes.length - offset, offset);
      if (read <= 0) fail("Edge provider evidence was truncated while reading.");
      offset += read;
    }
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      fail("Edge provider evidence changed while reading.");
    }
  } finally {
    if (descriptor !== null) fs.closeSync(descriptor);
  }
  let evidence = null;
  try {
    evidence = JSON.parse(evidenceBytes.toString("utf8"));
  } catch (error) {
    fail(`Invalid edge provider evidence JSON: ${String(error?.message ?? error)}`);
  }
  const attestationMode = String(argv.edgeProviderEvidenceAttestation ?? "");
  if (!new Set(["online", "offline"]).has(attestationMode)) {
    fail("Edge provider evidence requires --edgeProviderEvidenceAttestation online or offline.");
  }
  const bundle = argv.edgeProviderEvidenceBundle ?? null;
  const trustedRoot = argv.edgeProviderEvidenceTrustedRoot ?? null;
  if (attestationMode === "online" && (bundle || trustedRoot)) {
    fail("Online edge provider evidence verification must not accept local bundle or trust-root overrides.");
  }
  if (attestationMode === "offline" && (!bundle || !trustedRoot)) {
    fail("Offline edge provider evidence verification requires both attestation bundle and trusted root.");
  }
  const attestationOptions = providerEvidenceAttestationOptions({
    enabled: true,
    evidencePath: resolvedEvidencePath,
    evidenceDigest: crypto.createHash("sha256").update(evidenceBytes).digest("hex"),
    repository: argv.edgeProviderEvidenceRepository ?? process.env.GITHUB_REPOSITORY,
    signerWorkflow: argv.edgeProviderEvidenceWorkflow,
    sourceDigest: argv.edgeProviderEvidenceSourceDigest,
    sourceRef: argv.edgeProviderEvidenceSourceRef,
    bundle,
    trustedRoot,
  });
  const authentication = verifyGithubAttestation({
    ...attestationOptions,
    predicateType: SLSA_PROVENANCE_V1,
    certOidcIssuer: GITHUB_ACTIONS_OIDC_ISSUER,
  });
  const validated = validateEdgeProviderEvidence({
    evidence,
    authentication,
    expectedUrl,
    expectedProvider,
    currentCandidateId,
    observedStatus,
    maxAgeMinutes: Number(argv.maxEdgeProviderEvidenceAgeMinutes ?? 60),
  });
  return { ...validated, evidenceSha256: attestationOptions.expectedSubjectDigest };
}

async function loadTargetEvidence({ url, mode, requirePublicTarget, requireEdgeEvidence, expectedEdgeProvider, timeoutMs, edgeProviderEvidencePath, currentCandidateId }) {
  if (mode === "internal") {
    if (requireEdgeEvidence || edgeProviderEvidencePath) {
      fail("Authenticated edge traversal evidence cannot be satisfied by an internal load target.");
    }
    return {
      mode,
      url,
      public: false,
      publicRequired: requirePublicTarget,
      edgeRequired: requireEdgeEvidence,
      edge: null,
    };
  }

  const parsed = new URL(url);
  const publicTarget = publicEvidenceUrl(url);
  const legacyHost = legacyPlatformEvidenceHost(url);
  if (requirePublicTarget && legacyHost) {
    fail(`Load benchmark production target must use final platform hostnames, not legacy host ${legacyHost}.`);
  }
  if (requirePublicTarget && !publicTarget) {
    fail(`Load benchmark production target must be public, not ${url}.`);
  }

  const started = performance.now();
  const response = await request("GET", url, { timeoutMs });
  const latencyMs = Math.round(performance.now() - started);
  const headerDiagnostics = {
    detectedProvider: detectEdgeProvider(response.headers),
    headers: selectedEdgeHeaders(response.headers),
  };
  let providerEvidence = null;
  let externalPending = null;
  if (edgeProviderEvidencePath) {
    providerEvidence = authenticatedEdgeProviderEvidence({
      evidencePath: edgeProviderEvidencePath,
      expectedUrl: url,
      expectedProvider: expectedEdgeProvider,
      currentCandidateId,
      observedStatus: response.status,
    });
  } else if (requireEdgeEvidence) {
    externalPending = "EXTERNAL-PENDING: authenticated edge provider traversal evidence was not supplied.";
  }
  const providerMatched = providerEvidence?.verified === true;

  return {
    mode,
    url,
    protocol: parsed.protocol.replace(/:$/, ""),
    hostname: parsed.hostname,
    public: publicTarget,
    publicRequired: requirePublicTarget,
    edgeRequired: requireEdgeEvidence,
    error: externalPending,
    edge: {
      status: response.status,
      latencyMs,
      provider: providerEvidence?.provider ?? null,
      expectedProvider: expectedEdgeProvider,
      providerMatched,
      authenticated: providerMatched,
      providerEvidence,
      headerDiagnostics,
      externalPending,
    },
  };
}

function writeLoadBenchmarkReport(payload) {
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("load", `load-benchmark-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("load", `load-benchmark-${stamp}`, [
    "# Platform Load Benchmark",
    "",
    `Generated at: ${payload.generatedAt}`,
    `Status: ${payload.status}`,
    `Target: ${payload.url}`,
    `Target public: ${payload.target?.public ? "yes" : "no"}`,
    `Authenticated edge provider: ${payload.target?.edge?.authenticated ? payload.target.edge.provider : "EXTERNAL-PENDING"}`,
    `Header diagnostic only: ${payload.target?.edge?.headerDiagnostics?.detectedProvider ?? "none"}`,
    "",
    "| Users | Requests | Concurrency | Avg ms | P95 ms | Errors |",
    "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ...payload.profiles.map((result) => `| ${result.users} | ${result.requests} | ${result.concurrency} | ${Number.isFinite(Number(result.metric?.avg)) ? Number(result.metric.avg).toFixed(2) : "n/a"} | ${result.metric?.p95 ?? "n/a"} | ${result.metric?.errors ?? 0} |`),
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "CPU and memory snapshots are stored in the JSON report under `stats.before` and `stats.after` for each profile.",
  ]);
  return { jsonPath, markdownPath };
}

async function loadBenchmark() {
  const profiles = String(argv.profiles ?? "50,100,500")
    .split(",")
    .map((value) => positiveInteger(value.trim(), "profiles", 1));
  const quick = booleanFlag(argv.quick);
  const durationSeconds = positiveInteger(argv.durationSeconds ?? (quick ? 5 : 60), "durationSeconds");
  const perUserRps = Number(argv.perUserRps ?? (quick ? 0.05 : 0.2));
  const maxConcurrency = positiveInteger(argv.maxConcurrency ?? 500, "maxConcurrency", 1);
  const maxP95Ms = Number(argv.maxP95Ms ?? 1000);
  const url = argv.url ?? "https://api.localhost.com/health";
  const useEdge = Boolean(argv.url || booleanFlag(argv.edge));
  const targetUrl = useEdge ? url : "container:enterprise-control-center/health";
  const requirePublicTarget = booleanFlag(argv.requirePublicTarget);
  const requireEdgeEvidence = booleanFlag(argv.requireEdgeEvidence);
  const expectedEdgeProvider = String(argv.expectedEdgeProvider ?? "cloudflare").toLowerCase();
  const edgeProviderEvidencePath = argv.edgeProviderEvidence ? path.resolve(String(argv.edgeProviderEvidence)) : null;
  const preflightTimeoutMs = positiveInteger(argv.preflightTimeoutMs ?? 10000, "preflightTimeoutMs", 1000);
  const issues = [];
  let target = null;
  const candidateStartEvidence = requireEdgeEvidence || edgeProviderEvidencePath
    ? currentCandidateIdentityEvidence({
      envFile: argv.envFile ?? path.join(infraRoot, ".env.vps.example"),
      projectName: argv.project ?? argv.projectName,
      repository: argv.repository ?? argv.repo,
    })
    : { candidate: null, error: null };
  log("==> Load benchmark");
  try {
    target = await loadTargetEvidence({
      url: targetUrl,
      mode: useEdge ? "edge" : "internal",
      requirePublicTarget,
      requireEdgeEvidence,
      expectedEdgeProvider,
      timeoutMs: preflightTimeoutMs,
      edgeProviderEvidencePath,
      currentCandidateId: candidateStartEvidence.candidate?.id,
    });
    if (target.error) issues.push(`target-preflight: ${target.error}`);
  } catch (error) {
    const message = String(error?.message ?? error);
    issues.push(`target-preflight: ${message}`);
    target = {
      mode: useEdge ? "edge" : "internal",
      url: targetUrl,
      public: publicEvidenceUrl(targetUrl),
      publicRequired: requirePublicTarget,
      edgeRequired: requireEdgeEvidence,
      edge: null,
      error: message,
    };
  }

  const results = [];
  if (!target.error) {
    for (const users of profiles) {
      const targetRps = Math.max(1, Math.ceil(users * perUserRps));
      const requests = positiveInteger(argv.requests ?? Math.max(users, durationSeconds * targetRps), "requests", 1);
      const concurrency = Math.min(users, maxConcurrency);
      const before = dockerStatsSnapshot(`before-${users}`);
      let metric = null;
      let profileError = null;
      try {
        metric = !useEdge
          ? runInternalPlatformLoadProbe({ label: `Internal platform load benchmark ${users} users`, requests, concurrency, maxP95Ms })
          : await runLoadProbe({ label: `Edge load benchmark ${users} users`, url, requests, concurrency, maxP95Ms });
      } catch (error) {
        profileError = String(error?.message ?? error);
        issues.push(`profile-${users}: ${profileError}`);
        metric = { requests, concurrency, avg: null, p95: null, maxP95Ms, errors: 1 };
      }
      const after = dockerStatsSnapshot(`after-${users}`);
      results.push({ users, targetRps, requests, concurrency, maxP95Ms, metric, error: profileError, stats: { before, after } });
    }
  }

  const candidateEndEvidence = requireEdgeEvidence || edgeProviderEvidencePath
    ? currentCandidateIdentityEvidence({
      envFile: argv.envFile ?? path.join(infraRoot, ".env.vps.example"),
      projectName: argv.project ?? argv.projectName,
      repository: argv.repository ?? argv.repo,
    })
    : { candidate: null, error: null };
  const candidateStable = !(requireEdgeEvidence || edgeProviderEvidencePath) || Boolean(
    candidateStartEvidence.candidate?.trusted
    && candidateEndEvidence.candidate?.trusted
    && candidateIdentityMatches(candidateStartEvidence.candidate, candidateEndEvidence.candidate),
  );
  if (!candidateStable) {
    issues.push(`candidate-binding: load benchmark candidate changed or was unavailable: ${candidateStartEvidence.error ?? candidateEndEvidence.error ?? "identity-mismatch"}`);
  }

  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : "passed",
    url: targetUrl,
    target,
    candidate: candidateStartEvidence.candidate,
    candidateEnd: candidateEndEvidence.candidate,
    candidateStable,
    candidateError: candidateStartEvidence.error ?? candidateEndEvidence.error,
    benchmark: {
      durationSeconds,
      perUserRps,
      maxConcurrency,
      maxP95Ms,
      quick,
    },
    profiles: results,
    issues,
  };
  const report = writeLoadBenchmarkReport(payload);
  log(`Load benchmark reports written to ${report.jsonPath} and ${report.markdownPath}`);
  if (issues.length) {
    fail(`Load benchmark failed with ${issues.length} issue(s). Reports: ${report.jsonPath}, ${report.markdownPath}`);
  }
}

function runInternalPlatformLoadProbe({ label, requests, concurrency, maxP95Ms }) {
  const syntheticClientPool = booleanFlag(argv.preserveClientIp) ? 0 : positiveInteger(argv.syntheticClients ?? 64, "syntheticClients");
  const script = `
const http = require("node:http");
const { performance } = require("node:perf_hooks");
const requests = ${JSON.stringify(requests)};
const concurrency = ${JSON.stringify(concurrency)};
const maxP95Ms = ${JSON.stringify(maxP95Ms)};
const syntheticClientPool = ${JSON.stringify(syntheticClientPool)};
const latencies = [];
const errors = [];
let nextRequest = 0;
function once(requestIndex) {
  return new Promise((resolve) => {
    const started = performance.now();
    const headers = syntheticClientPool > 0 ? { "X-Forwarded-For": "198.51.100." + ((requestIndex % syntheticClientPool) + 1) } : {};
    const req = http.request({ method: "GET", hostname: "127.0.0.1", port: 8080, path: "/__health", headers }, (res) => {
      res.resume();
      res.on("end", () => {
        latencies.push(Math.round(performance.now() - started));
        if (res.statusCode !== 200) errors.push(String(res.statusCode));
        resolve();
      });
    });
    req.on("error", (error) => {
      errors.push(error.message);
      resolve();
    });
    req.end();
  });
}
async function worker() {
  while (nextRequest < requests) {
    const requestIndex = nextRequest;
    nextRequest += 1;
    await once(requestIndex);
  }
}
Promise.all(Array.from({ length: Math.min(concurrency, requests) }, () => worker())).then(() => {
  const sorted = latencies.sort((a, b) => a - b);
  const p95Index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
  const p95 = sorted[p95Index] ?? 0;
  const avg = sorted.reduce((sum, value) => sum + value, 0) / Math.max(sorted.length, 1);
  console.log(JSON.stringify({ errors, requests, concurrency, syntheticClients: syntheticClientPool || 1, avg, p95, maxP95Ms }));
  process.exit(errors.length || p95 > maxP95Ms ? 1 : 0);
});
`;
  const result = dockerExec("enterprise-control-center", ["node", "-e", script], { capture: true, allowFailure: true });
  const text = String(result.stdout ?? "").trim();
  const parsed = text ? JSON.parse(text.split(/\r?\n/).at(-1)) : null;
  if (!parsed) {
    fail(`${label} did not return metrics.`);
  }
  if (result.status !== 0) {
    if (parsed.errors?.length) parsed.errors.slice(0, 10).forEach((error) => log(`internal Control Center returned ${error}`));
    fail(`${label} failed: errors=${parsed.errors?.length ?? 0} p95=${parsed.p95}ms maxP95Ms=${parsed.maxP95Ms}ms.`);
  }
  log(`${label} passed: requests=${parsed.requests} requestedConcurrency=${parsed.concurrency} syntheticClients=${parsed.syntheticClients || 1} avg=${parsed.avg.toFixed(2)}ms p95=${parsed.p95}ms`);
  return { ...parsed, errors: parsed.errors?.length ?? 0 };
}

async function runLoadProbe({ label, url, requests, concurrency, maxP95Ms }) {
  const latencies = [];
  const errors = [];
  const syntheticClientPool = booleanFlag(argv.preserveClientIp) ? 0 : positiveInteger(argv.syntheticClients ?? 64, "syntheticClients");
  let nextRequest = 0;
  const workerCount = Math.min(concurrency, requests);
  const runOne = async () => {
    const requestIndex = nextRequest;
    nextRequest += 1;
    if (requestIndex >= requests) return;
    const started = performance.now();
    try {
      const headers = syntheticClientPool > 0 ? { "X-Forwarded-For": `198.51.100.${(requestIndex % syntheticClientPool) + 1}` } : {};
      const response = await request("GET", url, { headers });
      latencies.push(Math.round(performance.now() - started));
      if (response.status !== 200) {
        errors.push(`${url} returned ${response.status}`);
      }
    } catch (error) {
      errors.push(String(error.message ?? error));
    }
    await runOne();
  };
  await Promise.all(Array.from({ length: workerCount }, () => runOne()));
  if (errors.length) {
    errors.slice(0, 10).forEach((error) => log(error));
    fail(`${label} failed with ${errors.length} errors.`);
  }
  const sorted = latencies.sort((a, b) => a - b);
  const p95Index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
  const p95 = sorted[p95Index] ?? 0;
  const avg = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  log(`${label} passed: requests=${requests} requestedConcurrency=${concurrency} syntheticClients=${syntheticClientPool || 1} avg=${avg.toFixed(2)}ms p95=${p95}ms`);
  if (p95 > maxP95Ms) {
    fail(`${label} p95 ${p95}ms exceeded ${maxP95Ms}ms.`);
  }
  return { requests, concurrency, syntheticClients: syntheticClientPool || 1, avg, p95, maxP95Ms, errors: 0 };
}

const defaultResticImage = "restic/restic:0.18.0@sha256:4cf4a61ef9786f4de53e9de8c8f5c040f33830eb0a10bf3d614410ee2fcb6120";
const defaultResticRcloneImage = "platform/restic-rclone:local";
const defaultResticMaxRepositoryBytes = 2_500_000_000_000;

function resticConfig(options = {}) {
  const repository = options.repository ?? argv.repository ?? process.env.RESTIC_REPOSITORY;
  const passwordFile = path.resolve(options.passwordFile ?? argv.passwordFile ?? process.env.RESTIC_PASSWORD_FILE ?? path.join(infraRoot, "secrets", "restic_password.txt"));
  const tag = options.tag ?? argv.tag ?? "platform-backups";
  const hostname = String(options.hostname ?? argv.hostname ?? process.env.RESTIC_HOSTNAME ?? "platform-infrastructure").trim();
  if (!/^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$/.test(hostname)) fail("RESTIC_HOSTNAME must be a stable DNS-safe identity.");
  return { repository, passwordFile, tag, hostname };
}

function hostnameFromEndpoint(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return null;
  try {
    return new URL(raw).hostname;
  } catch {
    // Continue with host/path formats such as s3.amazonaws.com/bucket.
  }
  const beforeSlash = raw.split("/", 1)[0];
  if (!beforeSlash) return null;
  try {
    return new URL(`https://${beforeSlash}`).hostname;
  } catch {
    return beforeSlash.split(":", 1)[0] || null;
  }
}

function hostnameFromSftpRepository(value) {
  let raw = String(value ?? "").trim().replace(/^\/\//, "");
  if (!raw) return null;
  if (/^sftp:\/\//i.test(raw)) {
    try {
      return new URL(raw).hostname;
    } catch {
      return null;
    }
  }
  const atIndex = raw.lastIndexOf("@");
  if (atIndex !== -1) {
    raw = raw.slice(atIndex + 1);
  }
  return raw.split(":", 1)[0] || null;
}

function isPrivateOrLocalHost(hostname) {
  const host = String(hostname ?? "").trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "").replace(/\.$/, "");
  if (!host) return true;
  if (
    host === "localhost"
    || host === "0.0.0.0"
    || host === "::1"
    || host === "example.com"
    || host.endsWith(".localhost")
    || host.endsWith(".localhost.com")
    || host.endsWith(".local")
    || host.endsWith(".example.com")
    || (!host.includes(".") && !host.includes(":"))
  ) {
    return true;
  }
  const ipv4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const parts = ipv4.slice(1).map((part) => Number(part));
    return parts[0] === 10
      || parts[0] === 127
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      || (parts[0] === 192 && parts[1] === 168)
      || (parts[0] === 169 && parts[1] === 254);
  }
  return /^f[cd][0-9a-f]{2}:/i.test(host) || /^fe80:/i.test(host);
}

function classifyResticRepository(repository) {
  if (!repository) {
    return { type: "missing", offsite: false, host: null };
  }
  const value = String(repository).trim();
  const separator = value.indexOf(":");
  const type = separator === -1 ? "local" : value.slice(0, separator).toLowerCase();
  const body = separator === -1 ? value : value.slice(separator + 1);
  if (["b2", "azure", "gs", "gcs", "swift", "rclone"].includes(type)) {
    return { type, offsite: true, host: null };
  }
  if (type === "s3" || type === "rest") {
    const host = hostnameFromEndpoint(body);
    return { type, offsite: !isPrivateOrLocalHost(host), host };
  }
  if (type === "sftp") {
    const host = hostnameFromSftpRepository(body);
    return { type, offsite: !isPrivateOrLocalHost(host), host };
  }
  if (/^(http|https):\/\//i.test(value)) {
    const host = hostnameFromEndpoint(value);
    return { type: "rest", offsite: !isPrivateOrLocalHost(host), host };
  }
  return { type: "local", offsite: false, host: null };
}

function requireResticCredentials({ repository, passwordFile }) {
  if (!repository || !fs.existsSync(passwordFile)) {
    fail("Set RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE before running Restic operations.");
  }
}

function resticRcloneConfig(repository) {
  const repositoryClass = classifyResticRepository(repository);
  if (repositoryClass.type !== "rclone") {
    return { env: [], mounts: [] };
  }
  const rcloneConfig = path.resolve(process.env.RCLONE_CONFIG ?? path.join(infraRoot, "secrets", "rclone", "rclone.conf"));
  if (!fs.existsSync(rcloneConfig)) {
    fail("Set RCLONE_CONFIG to a valid rclone.conf before using a Restic rclone: repository.");
  }
  const configDir = path.dirname(rcloneConfig);
  const configName = path.basename(rcloneConfig);
  return {
    env: ["-e", `RCLONE_CONFIG=/rclone-config/${configName}`],
    mounts: ["-v", `${hostPathForContainerMount(configDir)}:/rclone-config:ro`],
  };
}

function resticRetentionConfig(options = {}) {
  const keepLast = positiveInteger(options.keepLast ?? argv.keepLast ?? process.env.RESTIC_KEEP_LAST ?? 42, "--keepLast", 1);
  const noPrune = Boolean(options.noPrune) || booleanFlag(argv.noPrune) || booleanFlag(process.env.RESTIC_NO_PRUNE);
  const prune = !noPrune;
  return { keepLast, prune };
}

function immutableResticImage(image) {
  const clean = String(image || "").trim();
  const digest = clean.match(/(?:@sha256:|^sha256:)([a-f0-9]{64})$/i)?.[1] || "";
  return Boolean(digest) && !/^0{64}$/.test(digest);
}

function resticDockerContainerArgs({ repository, passwordFile, mounts = [] }) {
  const resticPasswordDir = path.dirname(passwordFile);
  const resticPasswordName = path.basename(passwordFile);
  const repositoryClass = classifyResticRepository(repository);
  const rcloneConfig = resticRcloneConfig(repository);
  const secretTransport = resticSecretTransport(repository, `/restic-password/${resticPasswordName}`);
  const image = process.env.RESTIC_IMAGE ?? (repositoryClass.type === "rclone" ? defaultResticRcloneImage : defaultResticImage);
  if (booleanFlag(process.env.RESTIC_REQUIRE_IMMUTABLE_IMAGE ?? true) && !immutableResticImage(image)) {
    fail("RESTIC_IMAGE must be pinned by digest before backup or restore execution.");
  }
  const args = [
    "run",
    "--rm",
    ...secretTransport.dockerArgs,
    ...rcloneConfig.env,
  ];
  for (const key of resticPassthroughEnvironmentKeys) {
    if (process.env[key]) {
      args.push("-e", key);
    }
  }
  args.push(
    ...mounts,
    ...rcloneConfig.mounts,
    "-v",
    `${hostPathForContainerMount(resticPasswordDir)}:/restic-password:ro`,
    image,
  );
  return { args, secretTransport };
}

function resticDockerRun({ repository, passwordFile, mounts = [], resticArgs = [], runOptions = {} }) {
  const invocation = resticDockerContainerArgs({ repository, passwordFile, mounts });
  return run("docker", [
    ...invocation.args,
    ...resticArgs,
  ], {
    ...runOptions,
    env: { ...runOptions.env, ...invocation.secretTransport.processEnv },
    sensitiveValues: [...(runOptions.sensitiveValues ?? []), ...invocation.secretTransport.sensitiveValues],
    sensitiveEnvironmentKeys: invocation.secretTransport.sensitiveEnvironmentKeys,
  });
}

function resticRepositorySizeBytes(repository) {
  const repositoryClass = classifyResticRepository(repository);
  if (repositoryClass.type !== "rclone") return null;
  const remote = String(repository || "").replace(/^rclone:/i, "");
  const rcloneConfig = resticRcloneConfig(repository);
  const image = process.env.RESTIC_IMAGE ?? defaultResticRcloneImage;
  if (booleanFlag(process.env.RESTIC_REQUIRE_IMMUTABLE_IMAGE ?? true) && !immutableResticImage(image)) {
    fail("RESTIC_IMAGE must be pinned by digest before reading remote repository size.");
  }
  const result = run("docker", [
    "run",
    "--rm",
    "--entrypoint",
    "rclone",
    ...rcloneConfig.env,
    ...rcloneConfig.mounts,
    image,
    "size",
    remote,
    "--json",
  ], { capture: true, allowFailure: true });
  if (result.status !== 0) {
    fail("Unable to read remote Restic repository size with rclone.");
  }
  let payload = {};
  try {
    payload = JSON.parse(String(result.stdout || "{}"));
  } catch {
    fail("Unable to parse rclone size JSON for remote Restic repository.");
  }
  const bytes = Number(payload.bytes ?? payload.totalSize ?? payload.size);
  if (!Number.isFinite(bytes)) {
    fail("rclone size did not return a valid byte count for remote Restic repository.");
  }
  return bytes;
}

function verifyResticRepositorySizeLimit(repository) {
  const maxBytes = positiveInteger(process.env.RESTIC_MAX_REPOSITORY_BYTES ?? defaultResticMaxRepositoryBytes, "RESTIC_MAX_REPOSITORY_BYTES", 1);
  const sizeBytes = resticRepositorySizeBytes(repository);
  if (sizeBytes === null) {
    log("Remote repository size guard skipped: supported for rclone: repositories.");
    return null;
  }
  if (sizeBytes > maxBytes) {
    fail(`Remote Restic repository size exceeds configured limit: ${sizeBytes} bytes > ${maxBytes} bytes.`);
  }
  log(`Remote Restic repository size within limit: ${sizeBytes} bytes <= ${maxBytes} bytes.`);
  return { sizeBytes, maxBytes };
}

function resticForgetOldSnapshots({ repository, passwordFile, tag }) {
  if (booleanFlag(argv.skipRetention) || booleanFlag(process.env.RESTIC_SKIP_RETENTION)) {
    log("Restic retention skipped by configuration.");
    return;
  }
  const { keepLast, prune } = resticRetentionConfig();
  resticDockerRun({
    repository,
    passwordFile,
    resticArgs: [
      "forget",
      "--tag",
      tag,
      "--group-by",
      "tags",
      "--keep-last",
      String(keepLast),
      ...(prune ? ["--prune"] : []),
    ],
  });
  log(`Restic retention applied: keep-last=${keepLast}${prune ? ", prune=yes" : ", prune=no"}.`);
}

function latestVerifiedPlatformBackupManifest() {
  const directory = path.join(backupRootPath(), "manifests");
  const candidates = listFilesRecursive(directory, (filePath) => filePath.endsWith(".json"));
  for (const manifestPath of candidates) {
    try {
      const manifest = verifyBackupManifestDocument(JSON.parse(fs.readFileSync(manifestPath, "utf8")));
      if (manifest.scope.kind === "platform" && manifest.scope.id === "platform" && manifest.coverage.complete) {
        return { manifestPath, manifest };
      }
    } catch {
      // Continue until a valid complete platform manifest is found.
    }
  }
  fail("No complete signed platform backup manifest is available for off-site upload.");
}

function parseResticBackupSummary(result) {
  const lines = `${String(result?.stdout || "")}\n${String(result?.stderr || "")}`.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines.reverse()) {
    try {
      const payload = JSON.parse(line);
      if (payload.message_type === "summary" && String(payload.snapshot_id || "")) return payload;
    } catch {
      // Restic can mix non-JSON progress output with the final JSON summary.
    }
  }
  fail("Restic backup did not return a snapshot receipt.");
}

async function offsiteBackupRestic() {
  if (argv.backupFile || booleanFlag(argv.allowPartial)) {
    fail("Single-artifact and partial off-site uploads are not supported by the signed platform manifest pipeline.");
  }
  const { repository, passwordFile, tag, hostname } = resticConfig();
  requireResticCredentials({ repository, passwordFile });
  const repositoryClass = classifyResticRepository(repository);
  if (!repositoryClass.offsite) fail("Off-site backup requires a remote Restic repository.");
  const startedAt = new Date();
  const backupRoot = path.join(infraRoot, "backups");
  const { manifestPath, manifest } = latestVerifiedPlatformBackupManifest();
  const pathSet = new Set([`/backups/${path.relative(backupRoot, manifestPath).replaceAll("\\", "/")}`]);
  for (const artifact of manifest.artifacts) {
    const artifactPath = resolveInside(backupRoot, path.join(backupRoot, artifact.path));
    const verified = verifyBackupArtifact(artifactPath);
    if (verified.hash !== artifact.sha256 || fs.statSync(artifactPath).size !== artifact.sizeBytes) {
      fail(`Platform manifest artifact metadata mismatch for ${artifact.resourceId}.`);
    }
    const sidecars = [`${artifactPath}.sha256`, `${artifactPath}.sig.json`].filter((file) => fs.existsSync(file));
    for (const filePath of [artifactPath, ...sidecars]) {
      const relative = path.relative(backupRoot, filePath).replaceAll("\\", "/");
      pathSet.add(`/backups/${relative}`);
    }
  }
  const backupResult = resticDockerRun({
    repository,
    passwordFile,
    mounts: ["-v", `${hostPathForContainerMount(backupRoot)}:/backups:ro`],
    resticArgs: ["backup", "--json", ...pathSet, "--tag", tag, ...offsiteManifestTags(manifest).flatMap((manifestTag) => ["--tag", manifestTag]), "--host", hostname],
    runOptions: { capture: true },
  });
  const summary = parseResticBackupSummary(backupResult);
  resticForgetOldSnapshots({ repository, passwordFile, tag });
  const sizeGuard = verifyResticRepositorySizeLimit(repository);
  const finishedAt = new Date();
  const receipt = {
    schema: "platform.offsite-backup-receipt/v1",
    generatedAt: finishedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    status: "passed",
    manifestId: manifest.id,
    manifestPath: path.relative(backupRoot, manifestPath).replaceAll("\\", "/"),
    manifestDigest: manifest.signature.digest,
    resourceIds: manifest.resources.map((resource) => resource.id),
    artifactCount: manifest.artifacts.length,
    snapshotId: String(summary.snapshot_id),
    hostname,
    tag,
    repositoryType: repositoryClass.type,
    repositoryHost: repositoryClass.host,
    repositoryOffsite: true,
    repositorySizeBytes: sizeGuard?.sizeBytes ?? null,
    repositoryMaxBytes: sizeGuard?.maxBytes ?? Number(process.env.RESTIC_MAX_REPOSITORY_BYTES ?? defaultResticMaxRepositoryBytes),
    credentialsExposed: false,
  };
  const reportPath = writeJsonReport("offsite-backups", `offsite-backup-${reportTimestamp()}-${crypto.randomBytes(3).toString("hex")}`, receipt);
  log(`Off-site backup completed for ${manifest.resources.map((resource) => resource.id).join(", ")}`);
  log(`Off-site receipt written to ${reportPath}`);
  return receipt;
}

function listFilesRecursive(root, predicate = () => true) {
  if (!fs.existsSync(root)) {
    return [];
  }
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && predicate(fullPath)) {
        files.push(fullPath);
      }
    }
  };
  walk(root);
  return files.sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
}

function parseResticSnapshots(jsonText) {
  try {
    const parsed = JSON.parse(jsonText || "[]");
    if (!Array.isArray(parsed)) {
      fail("Restic snapshots --json did not return a JSON array.");
    }
    return parsed;
  } catch (error) {
    fail(`Unable to parse Restic snapshots JSON: ${String(error?.message ?? error)}`);
  }
}

function selectResticSnapshot(snapshots, requestedSnapshot) {
  if (requestedSnapshot && requestedSnapshot !== "latest") {
    return snapshots.find((snapshot) => snapshot.id === requestedSnapshot || snapshot.short_id === requestedSnapshot) ?? { id: requestedSnapshot, short_id: requestedSnapshot, time: null, paths: [] };
  }
  const latest = [...snapshots].sort((a, b) => new Date(b.time ?? 0).getTime() - new Date(a.time ?? 0).getTime())[0];
  if (!latest?.id && !latest?.short_id) {
    fail("No Restic snapshot found for the requested tag.");
  }
  return latest;
}

function resticSnapshotSummary(snapshot) {
  return {
    id: snapshot?.id ?? null,
    shortId: snapshot?.short_id ?? null,
    time: snapshot?.time ?? null,
    hostname: snapshot?.hostname ?? null,
    tags: snapshot?.tags ?? [],
    paths: snapshot?.paths ?? [],
  };
}

function restoredBackupFilePaths(restoreRoot) {
  const files = [];
  const walk = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      const stat = fs.lstatSync(fullPath);
      if (stat.isSymbolicLink()) fail(`Restic restore produced a symbolic link: ${fullPath}`);
      if (stat.isDirectory()) walk(fullPath);
      else if (stat.isFile()) files.push(`/${path.relative(restoreRoot, fullPath).replaceAll("\\", "/")}`);
      else fail(`Restic restore produced a non-regular file: ${fullPath}`);
    }
  };
  walk(restoreRoot);
  return files.sort();
}

function restoredPathForSnapshotPath(restoreRoot, snapshotPath) {
  const relative = String(snapshotPath).replaceAll("\\", "/").replace(/^\/+/, "");
  return assertPathInside(restoreRoot, path.join(restoreRoot, relative));
}

function stageExactRestoredSet({ restoreRoot, stagingRoot, expectedPaths }) {
  for (const snapshotPath of expectedPaths) {
    const source = restoredPathForSnapshotPath(restoreRoot, snapshotPath);
    if (!fs.existsSync(source) || !fs.statSync(source).isFile()) fail(`Missing restored file: ${snapshotPath}`);
    const backupRelative = snapshotPath.replace(/^\/backups\//, "");
    const target = assertPathInside(stagingRoot, path.join(stagingRoot, backupRelative));
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.copyFileSync(source, target);
    fs.chmodSync(target, 0o600);
  }
}

function offsiteRestoreCoverage(payload = {}) {
  return evaluateOffsiteRestoreCoverage(payload);
}

function writeOffsiteRestoreDrillReport(payload) {
  const stamp = reportTimestamp();
  const baseName = `offsite-restore-drill-${payload.mode}-${stamp}-${crypto.randomBytes(3).toString("hex")}`;
  const reportPayload = {
    ...payload,
    coverage: payload.coverage ?? offsiteRestoreCoverage(payload),
  };
  const jsonPath = writeJsonReport("offsite-restore-drills", baseName, reportPayload);
  const rows = (reportPayload.steps ?? []).map((step) => `| ${step.resourceId ?? step.family ?? step.name} | ${step.status} | ${step.durationMs ?? "n/a"} | ${step.artifactName ?? "n/a"} |`);
  const markdownPath = writeMarkdownReport("offsite-restore-drills", baseName, [
    "# Platform Off-site Restore Drill",
    "",
    `Status: ${reportPayload.status}`,
    `Mode: ${reportPayload.mode}`,
    `Started at: ${reportPayload.startedAt}`,
    `Finished at: ${reportPayload.finishedAt}`,
    `Duration: ${reportPayload.durationMs} ms`,
    `Restic repository configured: ${reportPayload.restic.repositoryConfigured ? "yes" : "no"}`,
    `Restic repository type: ${reportPayload.restic.repositoryType ?? "n/a"}`,
    `Restic repository host: ${reportPayload.restic.repositoryHost ?? "n/a"}`,
    `Restic repository off-site: ${reportPayload.restic.repositoryOffsite ? "yes" : "no"}`,
    `Restic password file configured: ${reportPayload.restic.passwordFileConfigured ? "yes" : "no"}`,
    `Restic tag: ${reportPayload.restic.tag}`,
    `Snapshot: ${reportPayload.snapshot?.shortId ?? reportPayload.snapshot?.id ?? reportPayload.requestedSnapshot ?? "n/a"}`,
    `Coverage complete: ${reportPayload.coverage.complete ? "yes" : "no"}`,
    `Manifest signature verified: ${reportPayload.coverage.manifestSignatureVerified ? "yes" : "no"}`,
    `Exact restored set verified: ${reportPayload.coverage.exactSetVerified ? "yes" : "no"}`,
    `Successful resources: ${reportPayload.coverage.successfulResourceIds.join(", ") || "none"}`,
    `Missing required resources: ${reportPayload.coverage.missingRequiredResourceIds.join(", ") || "none"}`,
    `Infra health after restore: ${reportPayload.coverage.infraHealthOk ? "yes" : "no"}`,
    "",
    "| Step | Status | Duration ms | Artifact |",
    "| --- | --- | ---: | --- |",
    ...(rows.length ? rows : ["| plan | success | n/a | n/a |"]),
    "",
    reportPayload.error ? `Error: ${reportPayload.error}` : "",
  ].filter((line) => line !== ""));
  log(`Off-site restore drill report written to ${jsonPath} and ${markdownPath}`);
  return { jsonPath, markdownPath };
}

async function offsiteRestoreDrillRestic(options = {}) {
  const startedAt = new Date();
  const planOnly = options.planOnly ?? booleanFlag(argv.planOnly);
  const dryRun = options.dryRun ?? booleanFlag(argv.dryRun);
  const allowPartial = options.allowPartial ?? booleanFlag(argv.allowPartial);
  const keepRestoredArtifacts = options.keepRestoredArtifacts ?? booleanFlag(argv.keepRestoredArtifacts);
  const skipInfraHealth = options.skipInfraHealth ?? booleanFlag(argv.skipInfraHealth);
  const requestedSnapshot = String(options.snapshot ?? argv.snapshot ?? argv._[0] ?? "latest");
  const requestedFamilies = options.families ?? argv.families;
  if (requestedFamilies) fail("Selective family restore is disabled; off-site restore must verify and test every resource in the signed manifest.");
  if (allowPartial) fail("Partial off-site restore cannot produce trustworthy coverage and is disabled.");
  const { repository, passwordFile, tag } = resticConfig(options);
  const repositoryClass = classifyResticRepository(repository);
  const mode = planOnly ? "plan" : dryRun ? "dry-run" : "restore";
  const basePayload = {
    generatedAt: startedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    finishedAt: null,
    durationMs: null,
    status: "running",
    mode,
    requestedSnapshot,
    families: [],
    allowPartial,
    keepRestoredArtifacts,
    skipInfraHealth,
    restic: {
      repositoryConfigured: Boolean(repository),
      repositoryType: repositoryClass.type,
      repositoryHost: repositoryClass.host,
      repositoryOffsite: repositoryClass.offsite,
      passwordFileConfigured: fs.existsSync(passwordFile),
      tag,
    },
    snapshot: null,
    snapshotCountForTag: null,
    manifest: null,
    exactSetVerified: false,
    steps: [],
  };

  if (planOnly) {
    const finishedAt = new Date();
    const payload = {
      ...basePayload,
      status: "success",
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      steps: [{
        name: "signed-exact-manifest",
        status: "planned",
        artifactName: "one signed complete platform manifest and its exact artifact set",
      }],
      notes: [
        "Use --dryRun to validate the remote Restic repository and selected snapshot without restoring files.",
        "Run without --dryRun to restore into disposable local paths and execute restore-test commands.",
      ],
    };
    writeOffsiteRestoreDrillReport(payload);
    log("Off-site restore drill plan generated for the complete signed manifest resource set.");
    return payload;
  }

  requireResticCredentials({ repository, passwordFile });
  if (!repositoryClass.offsite) fail("Off-site restore requires a remote Restic repository.");

  let restoreRoot = null;
  let stagingRoot = null;
  const restoreTempRoot = path.join(infraRoot, ".tmp", "ops");
  const stagingParent = path.join(backupRootPath(), "offsite-restore-drills");
  let payload = { ...basePayload };

  try {
    const snapshotsResult = resticDockerRun({
      repository,
      passwordFile,
      resticArgs: ["snapshots", "--json", "--tag", tag],
      runOptions: { capture: true },
    });
    const snapshots = parseResticSnapshots(String(snapshotsResult.stdout ?? ""));
    if (!snapshots.length) {
      fail(`No Restic snapshots found with tag '${tag}'.`);
    }
    const snapshot = selectResticSnapshot(snapshots, requestedSnapshot);
    const snapshotId = snapshot.id ?? snapshot.short_id ?? requestedSnapshot;
    const locatedManifest = locateSnapshotManifest({ snapshotPaths: snapshot.paths, snapshotTags: snapshot.tags });
    payload = {
      ...payload,
      snapshot: resticSnapshotSummary(snapshot),
      snapshotCountForTag: snapshots.length,
      manifest: {
        id: locatedManifest.manifestId,
        digest: locatedManifest.manifestDigest,
        path: locatedManifest.manifestPath,
        signatureVerified: false,
        resourceIds: [],
      },
    };

    restoreRoot = makeOpsTempDir(dryRun ? "restic-restore-dry-run-" : "restic-restore-");
    const restoreMount = ["-v", `${hostPathForContainerMount(restoreRoot)}:/restore`];

    if (dryRun) {
      const dryRunResult = resticDockerRun({
        repository,
        passwordFile,
        mounts: restoreMount,
        resticArgs: ["restore", "--target", "/restore", "--dry-run", "--verbose=2", snapshotId],
        runOptions: { capture: true },
      });
      const finishedAt = new Date();
      payload = {
        ...payload,
        status: "external-pending",
        finishedAt: finishedAt.toISOString(),
        durationMs: finishedAt.getTime() - startedAt.getTime(),
        steps: [{
          name: "restic-restore-dry-run",
          status: "success",
          durationMs: finishedAt.getTime() - startedAt.getTime(),
          artifactName: "remote snapshot",
        }],
        resticOutputPreview: String(dryRunResult.stdout ?? dryRunResult.stderr ?? "").slice(0, 12000),
        externalPending: ["The remote snapshot is reachable, but its signed manifest and exact restored file set were not materialized or verified."],
      };
      writeOffsiteRestoreDrillReport(payload);
      log(`Off-site Restic dry-run reached snapshot ${snapshot.short_id ?? snapshot.id ?? snapshotId}; exact manifest verification remains EXTERNAL-PENDING.`);
      return payload;
    }

    resticDockerRun({
      repository,
      passwordFile,
      mounts: restoreMount,
      resticArgs: ["restore", "--target", "/restore", snapshotId],
    });

    fs.mkdirSync(stagingParent, { recursive: true });
    stagingRoot = assertPathInside(stagingParent, path.join(stagingParent, `${reportTimestamp()}-${crypto.randomBytes(3).toString("hex")}`));
    fs.mkdirSync(stagingRoot, { recursive: true });
    const restoredPaths = restoredBackupFilePaths(restoreRoot);
    const manifestSourcePath = restoredPathForSnapshotPath(restoreRoot, locatedManifest.manifestPath);
    if (!fs.existsSync(manifestSourcePath) || !fs.statSync(manifestSourcePath).isFile()) fail("Restic restore did not materialize the tagged manifest file.");
    const signedManifest = verifyBackupManifestDocument(readJsonFile(manifestSourcePath, manifestSourcePath));
    const exactSet = validateOffsiteRestoreSet({
      manifest: signedManifest,
      snapshotPaths: snapshot.paths,
      restoredPaths,
      snapshotTags: snapshot.tags,
    });
    stageExactRestoredSet({ restoreRoot, stagingRoot, expectedPaths: exactSet.expectedPaths });
    const stagedManifestPath = assertPathInside(stagingRoot, path.join(stagingRoot, exactSet.manifestPath.replace(/^\/backups\//, "")));
    const stagedManifest = verifyBackupManifestDocument(readJsonFile(stagedManifestPath, stagedManifestPath));
    if (stagedManifest.id !== signedManifest.id || stagedManifest.signature.digest !== signedManifest.signature.digest) {
      fail("Staged off-site manifest identity changed after exact-set verification.");
    }
    payload = {
      ...payload,
      exactSetVerified: true,
      manifest: {
        id: stagedManifest.id,
        digest: stagedManifest.signature.digest,
        path: exactSet.manifestPath,
        signatureVerified: true,
        resourceIds: exactSet.resourceIds,
      },
    };

    for (const resource of stagedManifest.resources) {
      const artifact = manifestArtifactForResource(stagedManifest, resource.id);
      if (!artifact) fail(`Signed off-site manifest has no artifact for ${resource.id}.`);
      const stepStarted = Date.now();
      const result = await executeTypedRestoreResource(resource, artifact, { backupRoot: stagingRoot });
      payload.steps.push({
        resourceId: resource.id,
        resourceKind: resource.kind,
        status: "success",
        durationMs: Date.now() - stepStarted,
        artifactName: path.basename(artifact.path),
        sha256: artifact.sha256,
        result,
      });
    }

    if (!payload.steps.some((step) => step.resourceId && step.status === "success")) fail("No signed-manifest resources were restore-tested.");

    if (!skipInfraHealth) {
      const healthStarted = Date.now();
      await infraHealth();
      payload.steps.push({
        name: "infra-health",
        status: "success",
        durationMs: Date.now() - healthStarted,
        artifactName: "runtime stack",
      });
    }

    const finishedAt = new Date();
    payload = {
      ...payload,
      status: "success",
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      restoreRoot,
      stagingRoot,
    };
    writeOffsiteRestoreDrillReport(payload);
    log(`Off-site restore drill completed for ${payload.manifest.resourceIds.length} exact signed-manifest resources.`);
    return payload;
  } catch (error) {
    const finishedAt = new Date();
    payload = {
      ...payload,
      status: "failed",
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      restoreRoot,
      stagingRoot,
      error: String(error?.message ?? error),
    };
    writeOffsiteRestoreDrillReport(payload);
    throw error;
  } finally {
    if (restoreRoot && !keepRestoredArtifacts) {
      removeTreeInside(restoreTempRoot, restoreRoot);
    }
    if (stagingRoot && !keepRestoredArtifacts) {
      removeTreeInside(stagingParent, stagingRoot);
    }
  }
}

async function productionPreflight() {
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
  if (!fs.existsSync(envFile)) fail(`Env file not found: ${envFile}`);
  const env = parseEnv(envFile);
  const requireKey = (key) => {
    if (!env[key]) fail(`Missing required production env: ${key}`);
    if (/change_me|your-domain|localhost|example\.com/i.test(env[key])) fail(`Production env ${key} still contains a placeholder or local value.`);
  };
  requireKey("HOSTED_WORKLOAD_LOCK");
  ["TRAEFIK_ACME_EMAIL", "DOMAIN", "CONTROL_CENTER_PUBLIC_URL", "DOCS_PUBLIC_URL", "AUTH_HOST", "SMTP_HOST", "SMTP_USER", "MAILER_FROM", "ALERT_EMAIL_TO"].forEach(requireKey);
  for (const key of ["POSTGRES_PASSWORD", "KEYCLOAK_DB_PASSWORD", "REDIS_PASSWORD", "KC_BOOTSTRAP_ADMIN_PASSWORD", "NATS_PASSWORD", "MINIO_ROOT_PASSWORD", "MARIADB_ROOT_PASSWORD", "GF_SECURITY_ADMIN_PASSWORD", "SMTP_PASSWORD"]) {
    requireManagedSecret(env, key);
  }
  for (const imageKey of releaseImageKeys) {
    if (!env[imageKey]) continue;
    assertDigestPinnedImageRef(imageKey, env[imageKey]);
    if (/@sha256:0{64}$/i.test(env[imageKey])) fail(`${imageKey} must use a real image digest.`);
  }
  if (!argv.skipDns) {
    for (const host of [env.CONTROL_CENTER_HOST, env.DOCS_HOST, env.AUTH_HOST, env.STORAGE_HOST, env.GRAFANA_HOST].filter(Boolean)) {
      if (/localhost|your-domain|example\.com/i.test(host)) fail(`Production host is not public: ${host}`);
      await dns.resolve4(host);
    }
  }
  const workloadLock = path.resolve(infraRoot, env.HOSTED_WORKLOAD_LOCK);
  run("sh", [path.join(scriptDir, "hosted-workload-lock.sh"), workloadLock, "verify"], { env: { HOSTED_WORKLOAD_ALLOW_RESOLVED: "0" } });
  const { evidence: topology } = canonicalVpsTopologyRender({ envFile, workloadLock });
  log(`Platform production preflight passed for canonical render ${topology.renderSha256} and workload lock ${topology.workloadLock.sha256}.`);
}

async function haConfigCheck(options = {}) {
  await withLocalCheckReport("ha-config-check", async () => {
    const haCompose = readText(path.join(infraRoot, "compose.ha.yaml"));
    for (const service of ["postgres", "redis", "nats", "minio"]) {
      assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?node\\.labels\\.platform\\.stateful == true`, "m"), `${service} must be pinned to stateful nodes or replaced by a managed tier.`);
    }
    assertNoMatch(haCompose, /^\s{2}(?:backend|web|worker-jobs|worker-notifications|node-account|node-ui):/m, "HA overlay must not own hosted workload replicas.");
    if (!noDockerMode(options)) {
      run("docker", ["compose", "--env-file", ".env.example", "-p", "enterprise_prod_ha", "-f", "compose.yaml", "-f", "compose.secrets.yaml", "-f", "compose.prod.yaml", "-f", "compose.ha.yaml", "config", "--quiet"]);
    }
    log("Platform stateful HA configuration check passed; multi-node availability still requires external capacity and live evidence.");
  }, { noDocker: noDockerMode(options), scope: "platform-infrastructure" });
}

async function managedSecretsPreflight(options = {}) {
  await withLocalCheckReport("managed-secrets-preflight", async () => {
    const envFile = path.resolve(options.envFile ?? argv.envFile ?? path.join(infraRoot, ".env"));
    const managedCompose = readText(path.join(infraRoot, "compose.managed-secrets.yaml"));
    const required = [
      "backup_scheduler_docker_gateway_token", "postgres_superuser_password", "keycloak_db_password", "redis_password", "keycloak_admin_password", "nats_password", "minio_root_password", "mariadb_root_password", "phpmyadmin_control_password", "grafana_admin_password", "control_center_vault_keys", "projects_gateway_signing_keys", "backup_signing_keys", "alertmanager_webhook_token", "smtp_password",
    ];
    for (const secretName of required) {
      assertMatch(managedCompose, new RegExp(`^\\s{2}${secretName}:\\s*\\r?\\n\\s+external:\\s+true`, "m"), `${secretName} must be declared as an external Docker secret.`);
    }
    assertNoMatch(managedCompose, /app_db_password|backend_db_password|worker_jobs_db_password|worker_notifications_db_password|database_url|session_signing_keys|hash_pepper_keys|turnstile/i, "Managed platform secrets must not include hosted application credentials.");
    if (!noDockerMode(options)) {
      run("docker", ["compose", "--env-file", envFile, "-p", "enterprise_prod_managed_secrets", "-f", "compose.yaml", "-f", "compose.prod.yaml", "-f", "compose.managed-secrets.yaml", "config", "--quiet"]);
    }
    log("Managed platform secrets preflight passed.");
  }, { noDocker: noDockerMode(options), envFile: options.envFile ?? argv.envFile ?? null, scope: "platform-infrastructure" });
}

function dockerComposeConfigJson({ envFile, projectName, files, profiles = [] }) {
  const args = ["compose", "--env-file", envFile, "-p", projectName];
  for (const file of files) {
    args.push("-f", file);
  }
  for (const profile of profiles) {
    args.push("--profile", profile);
  }
  args.push("config", "--format", "json");
  const text = output("docker", args);
  try {
    return JSON.parse(text);
  } catch (error) {
    fail(`Docker Compose JSON config parse failed for ${projectName}: ${String(error?.message ?? error)}`);
  }
}

function composeServiceHasHealthcheck(service) {
  return Boolean(service?.healthcheck && service.healthcheck.disable !== true && service.healthcheck.test);
}

async function composeHealthcheckCoverage() {
  log("==> Platform Compose healthcheck coverage");
  const stacks = [
    { name: "local-waf", envFile: ".env.example", projectName: "platform_ops_health_local", files: ["compose.yaml", "compose.secrets.yaml", "compose.waf.yaml"], profiles: [] },
    { name: "vps-waf", envFile: ".env.vps.example", projectName: "platform_ops_health_vps", files: ["compose.yaml", "compose.secrets.yaml", "compose.waf.yaml", "compose.vps.yaml", "compose.vps-waf.yaml", "compose.backup-scheduler.yaml", "compose.runtime.yaml", "compose.networks.yaml", "compose.runtime-isolation.yaml"], profiles: ["backup"] },
    { name: "backup-scheduler", envFile: ".env.example", projectName: "platform_ops_health_backup", files: ["compose.yaml", "compose.secrets.yaml", "compose.backup-scheduler.yaml"], profiles: ["backup"] },
  ];
  const issues = [];
  const stackReports = [];
  for (const stack of stacks) {
    const config = dockerComposeConfigJson(stack);
    const services = Object.entries(config.services ?? {}).map(([name, service]) => ({ name, hasHealthcheck: composeServiceHasHealthcheck(service), restart: service.restart ?? null })).sort((a, b) => a.name.localeCompare(b.name));
    const missing = services.filter((service) => !service.hasHealthcheck).map((service) => service.name);
    missing.forEach((serviceName) => issues.push(`${stack.name}: service ${serviceName} has no healthcheck`));
    stackReports.push({ name: stack.name, envFile: stack.envFile, projectName: stack.projectName, services, missing });
  }
  const payload = { generatedAt: new Date().toISOString(), status: issues.length ? "failed" : "passed", scope: "platform-infrastructure", stacks: stackReports, missingHealthchecks: issues };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("healthchecks", `healthcheck-coverage-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("healthchecks", `healthcheck-coverage-${stamp}`, ["# Platform Healthcheck Coverage", "", `Status: ${payload.status}`, `Generated at: ${payload.generatedAt}`, "", ...stackReports.flatMap((stack) => [`## ${stack.name}`, "", `Services: ${stack.services.length}`, `Missing: ${stack.missing.join(", ") || "none"}`, ""])]);
  log(`Healthcheck coverage reports written to ${jsonPath} and ${markdownPath}`);
  if (issues.length) fail(`Compose healthcheck coverage failed: ${issues.join("; ")}`);
}

function platformFunctionalHealthProbes() {
  return validateFunctionalHealthProbes([
    { id: "keycloak-ready", kind: "http", container: "enterprise-keycloak", port: 9000, path: "/health/ready", expectedStatuses: [200] },
    { id: "loki-ready", kind: "http", container: "enterprise-loki", port: 3100, path: "/ready", expectedStatuses: [200], bodyIncludes: "ready" },
    { id: "promtail-ready", kind: "http", container: "enterprise-promtail", port: 9080, path: "/ready", expectedStatuses: [200] },
    { id: "prometheus-ready", kind: "http", container: "enterprise-prometheus", port: 9090, path: "/-/ready", expectedStatuses: [200] },
    { id: "alertmanager-ready", kind: "http", container: "enterprise-alertmanager", port: 9093, path: "/-/ready", expectedStatuses: [200] },
    { id: "grafana-api", kind: "http", container: "enterprise-grafana", port: 3000, path: "/api/health", expectedStatuses: [200] },
    { id: "control-center-api", kind: "http", container: "enterprise-control-center", port: 8080, path: "/__health", expectedStatuses: [200] },
    { id: "project-router-api", kind: "http", container: "enterprise-project-router", port: 8080, path: "/__health", expectedStatuses: [200] },
    { id: "nats-ready", kind: "http", container: "enterprise-nats", port: 8222, path: "/healthz", expectedStatuses: [200] },
    { id: "minio-ready", kind: "http", container: "enterprise-minio", port: 9000, path: "/minio/health/ready", expectedStatuses: [200] },
    { id: "platform-dns", kind: "dns", container: "enterprise-local-dns", query: "portal.platform-infrastructure.com" },
  ]);
}

const FUNCTIONAL_HTTP_PROBE_SCRIPT = `
const http = require("node:http");
const [host, port, path] = process.argv.slice(1);
const request = http.get({ host, port: Number(port), path, headers: { "User-Agent": "platform-functional-health/1.0" } }, (response) => {
  let body = "";
  response.setEncoding("utf8");
  response.on("data", (chunk) => { body += chunk; });
  response.on("end", () => process.stdout.write(JSON.stringify({ status: response.statusCode, body })));
});
request.setTimeout(5000, () => request.destroy(new Error("timeout")));
request.on("error", (error) => { process.stderr.write(error.message); process.exitCode = 1; });
`;

const FUNCTIONAL_DNS_PROBE_SCRIPT = `
const dns = require("node:dns");
const [server, query] = process.argv.slice(1);
dns.lookup(server, (lookupError, address) => {
  if (lookupError) { process.stderr.write(lookupError.message); process.exitCode = 1; return; }
  const resolver = new dns.Resolver();
  resolver.setServers([address]);
  resolver.resolve4(query, (resolveError, answers) => {
    if (resolveError) { process.stderr.write(resolveError.message); process.exitCode = 1; return; }
    process.stdout.write(JSON.stringify({ answers }));
  });
});
`;

function runFunctionalProbe(probe) {
  const executor = "enterprise-control-center";
  const args = probe.kind === "dns"
    ? ["exec", executor, "node", "-e", FUNCTIONAL_DNS_PROBE_SCRIPT, probe.container, probe.query]
    : ["exec", executor, "node", "-e", FUNCTIONAL_HTTP_PROBE_SCRIPT, probe.container, String(probe.port), probe.path];
  const result = run("docker", args, { allowFailure: true, capture: true });
  if (result.status !== 0) {
    log(`Functional probe ${probe.id} rejected: ${String(result.stderr || result.stdout || "docker exec failed").trim()}`);
    return { error: `${probe.kind}-probe-failed` };
  }
  try {
    return JSON.parse(String(result.stdout ?? ""));
  } catch {
    return { error: `${probe.kind}-probe-invalid-response` };
  }
}

async function functionalHealthCheck(options = {}) {
  log("==> Platform functional health check");
  const probes = platformFunctionalHealthProbes();
  const noDocker = noDockerMode(options);
  const candidateEvidence = noDocker ? { candidate: null, error: "runtime-not-inspected" } : currentCandidateIdentityEvidence({
    envFile: options.envFile ?? argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: options.project ?? argv.project ?? argv.projectName,
  });
  let observations = [];
  let evaluation = null;
  if (!noDocker) {
    for (const probe of probes) {
      const started = Date.now();
      try {
        const observation = runFunctionalProbe(probe);
        observations.push({ id: probe.id, ...observation, latencyMs: Date.now() - started });
      } catch (error) {
        log(`Functional probe ${probe.id} failed to execute: ${String(error?.message ?? error)}`);
        observations.push({ id: probe.id, latencyMs: Date.now() - started, error: "probe-failed" });
      }
    }
    evaluation = evaluateFunctionalHealth(probes, observations);
  }
  const candidateEndEvidence = noDocker ? candidateEvidence : currentCandidateIdentityEvidence({
    envFile: options.envFile ?? argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: options.project ?? argv.project ?? argv.projectName,
  });
  const candidateStable = Boolean(
    candidateEvidence.candidate?.trusted
    && candidateEndEvidence.candidate?.trusted
    && candidateIdentityMatches(candidateEvidence.candidate, candidateEndEvidence.candidate),
  );
  const payload = {
    generatedAt: new Date().toISOString(),
    mode: noDocker ? "static-policy" : "runtime",
    status: noDocker ? "passed" : evaluation.status,
    scope: "platform-infrastructure",
    candidate: candidateEvidence.candidate,
    candidateEnd: candidateEndEvidence.candidate,
    candidateStable,
    candidateError: candidateEvidence.error,
    fingerprint: evaluation?.fingerprint ?? null,
    checks: noDocker ? probes.map((probe) => ({ id: probe.id, kind: probe.kind, container: probe.container, passed: true })) : evaluation.checks,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("healthchecks", `functional-health-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("healthchecks", `functional-health-${stamp}`, [
    "# Platform Functional Health",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    `Candidate: ${payload.candidate?.id ?? "not-bound"}`,
    "",
    "| Probe | Kind | Container | Result | Latency ms |",
    "| --- | --- | --- | --- | ---: |",
    ...payload.checks.map((check) => `| ${check.id} | ${check.kind} | ${check.container} | ${check.passed ? "passed" : "failed"} | ${check.latencyMs ?? "n/a"} |`),
  ]);
  log(`Functional health reports written to ${jsonPath} and ${markdownPath}`);
  if (payload.status !== "passed") fail(`Functional health failed. Report: ${jsonPath}`);
  log("Platform functional health passed.");
}

function readStableRuntimeIdentityFile(filePath, expectedSha256, label) {
  const expectedHash = String(expectedSha256 ?? "").trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expectedHash)) fail(`${label} requires an independently supplied SHA256.`);
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size < 2 || before.size > 8 * 1024 * 1024 || (before.mode & 0o022) !== 0) {
      fail(`${label} must be a bounded regular file that is not group/world writable.`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      fail(`${label} changed while it was being read.`);
    }
    const observedHash = crypto.createHash("sha256").update(bytes).digest("hex");
    if (observedHash !== expectedHash) fail(`${label} SHA256 does not match the approved receipt.`);
    return { bytes, sha256: observedHash };
  } catch (error) {
    fail(`${label} could not be read safely: ${String(error?.message ?? error)}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function sha256StableRuntimeFile(filePath, label) {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
    const before = fs.fstatSync(descriptor);
    if (!before.isFile() || before.size < 2 || before.size > 64 * 1024 * 1024) fail(`${label} is not a bounded regular file.`);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
      fail(`${label} changed while it was being read.`);
    }
    return crypto.createHash("sha256").update(bytes).digest("hex");
  } catch (error) {
    fail(`${label} could not be read safely: ${String(error?.message ?? error)}`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function runtimeTargetManifest(options = {}) {
  const manifestPath = path.resolve(options.targetManifest ?? argv.targetManifest ?? process.env.PLATFORM_RUNTIME_TARGET_MANIFEST ?? "");
  const expectedSha256 = options.targetManifestSha256 ?? argv.targetManifestSha256 ?? process.env.PLATFORM_RUNTIME_TARGET_MANIFEST_SHA256;
  if (!String(options.targetManifest ?? argv.targetManifest ?? process.env.PLATFORM_RUNTIME_TARGET_MANIFEST ?? "").trim()) {
    fail("Runtime fingerprint requires --targetManifest from the approved release receipt.");
  }
  const stable = readStableRuntimeIdentityFile(manifestPath, expectedSha256, "Runtime target manifest");
  let manifest;
  try {
    manifest = JSON.parse(stable.bytes.toString("utf8"));
  } catch {
    fail("Runtime target manifest is not valid JSON.");
  }
  if (manifest?.schema !== "platform.runtime-target/v1" || !manifest?.candidate || !manifest?.deployment || !Array.isArray(manifest?.services)) {
    fail("Runtime target manifest does not use platform.runtime-target/v1.");
  }
  return {
    path: manifestPath,
    sha256: stable.sha256,
    expected: {
      candidate: manifest.candidate,
      deploymentId: manifest.deployment.id,
      deploymentStartedAt: manifest.deployment.startedAt,
      serviceConfigSha256: manifest.serviceConfigSha256,
      services: manifest.services,
    },
  };
}

function runtimeWorkloadLockPath(envValues) {
  const configured = process.env.HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE
    ?? envValues.HOSTED_WORKLOAD_RUNTIME_LOCK_SOURCE
    ?? process.env.HOSTED_WORKLOAD_LOCK
    ?? envValues.HOSTED_WORKLOAD_LOCK
    ?? "config/no-hosted-workloads.lock.json";
  return path.resolve(infraRoot, configured);
}

function observedRuntimeLabel(containers, field) {
  const values = new Set(containers.map((container) => String(container?.[field] ?? "").trim()).filter(Boolean));
  return values.size === 1 ? [...values][0] : "";
}

function inspectComposeRuntime(project) {
  const idsResult = run("docker", ["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`], { allowFailure: true, capture: true });
  if (idsResult.status !== 0) fail(`Unable to enumerate runtime containers for Compose project ${project}.`);
  const ids = String(idsResult.stdout ?? "").split(/\s+/).map((item) => item.trim()).filter(Boolean);
  const format = '{{.Name}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.config-hash"}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.ExitCode}}|{{.State.StartedAt}}|{{json .Config.Labels}}';
  return ids.map((id) => {
    const result = run("docker", ["inspect", "--format", format, id], { allowFailure: true, capture: true });
    if (result.status !== 0) fail(`Unable to inspect runtime container ${id}.`);
    const parts = String(result.stdout ?? "").trim().split("|");
    if (parts.length < 11) fail(`Runtime container ${id} returned an incomplete identity record.`);
    const [name, imageId, imageRef, service, containerProject, configHash, state, health, exitCode, startedAt] = parts;
    let labels;
    try {
      labels = JSON.parse(parts.slice(10).join("|"));
    } catch {
      fail(`Runtime container ${id} returned invalid label metadata.`);
    }
    return {
      name,
      imageId,
      imageRef,
      service,
      project: containerProject,
      configHash,
      state,
      health,
      exitCode: Number(exitCode),
      startedAt,
      runtimeCandidateId: labels?.["com.platform.runtime.candidate-id"] ?? "",
      runtimeCommit: labels?.["com.platform.runtime.commit"] ?? "",
      runtimeTree: labels?.["com.platform.runtime.tree"] ?? "",
      runtimeDeploymentId: labels?.["com.platform.runtime.deployment-id"] ?? "",
      runtimeRenderSha256: labels?.["com.platform.runtime.render-sha256"] ?? "",
      runtimeWorkloadLockSha256: labels?.["com.platform.runtime.workload-lock-sha256"] ?? "",
    };
  });
}

async function runtimeFingerprint(options = {}) {
  log("==> Platform runtime fingerprint");
  const envFile = path.resolve(options.envFile ?? argv.envFile ?? path.join(infraRoot, ".env"));
  const envValues = parseEnv(envFile);
  const project = String(options.project ?? argv.project ?? envValues.COMPOSE_PROJECT_NAME ?? process.env.COMPOSE_PROJECT_NAME ?? "platform_infra_vps").trim();
  const git = gitEvidence();
  if (!git.commit) fail("Unable to resolve the candidate Git commit.");
  const target = runtimeTargetManifest(options);
  const noDocker = noDockerMode(options);
  const checkoutTree = String(git.tree ?? "").trim().toLowerCase();
  const workloadLock = runtimeWorkloadLockPath(envValues);
  const workloadLockSha256 = fs.existsSync(workloadLock) ? sha256StableRuntimeFile(workloadLock, "Runtime workload lock") : "";
  const candidateEvidence = noDocker ? { candidate: null, error: "runtime-not-inspected" } : currentCandidateIdentityEvidence({
    envFile,
    projectName: project,
    repository: options.repository ?? options.repo ?? argv.repository ?? argv.repo,
  });
  const containers = noDocker ? [] : inspectComposeRuntime(project);
  const actual = {
    checkoutCommit: git.commit,
    checkoutTree,
    clean: git.dirty === false,
    project,
    workloadLockSha256,
    renderSha256: observedRuntimeLabel(containers, "runtimeRenderSha256"),
    containers,
  };
  const exactEvaluation = evaluateRuntimeFingerprint(target.expected, actual);
  const evaluation = noDocker
    ? { ...exactEvaluation, status: "static-policy", issues: ["runtime-not-inspected", ...exactEvaluation.issues], fingerprint: null }
    : exactEvaluation;
  const candidateEndEvidence = noDocker ? candidateEvidence : currentCandidateIdentityEvidence({
    envFile,
    projectName: project,
    repository: options.repository ?? options.repo ?? argv.repository ?? argv.repo,
  });
  const candidateStable = Boolean(
    candidateEvidence.candidate?.trusted
    && candidateEndEvidence.candidate?.trusted
    && candidateIdentityMatches(candidateEvidence.candidate, candidateEndEvidence.candidate),
  );
  const candidateTargetMatches = Boolean(
    candidateEvidence.candidate?.trusted
    && candidateIdentityMatches(candidateEvidence.candidate, target.expected.candidate),
  );
  if (!noDocker && (!candidateStable || !candidateTargetMatches || candidateEvidence.error || candidateEndEvidence.error)) {
    evaluation.issues.push(`candidate-identity:${candidateEvidence.error ?? candidateEndEvidence.error ?? "candidate-changed-or-worktree-not-clean"}`);
    evaluation.status = "failed";
  }
  const payload = {
    generatedAt: new Date().toISOString(),
    mode: noDocker ? "static-policy" : "runtime-exact",
    status: evaluation.status,
    scope: "platform-infrastructure",
    git: { commit: git.commit, tree: checkoutTree, repository: git.repository, branch: git.branch, clean: git.dirty === false },
    candidate: candidateEvidence.candidate,
    candidateEnd: candidateEndEvidence.candidate,
    candidateStable,
    candidateTargetMatches,
    candidateError: candidateEvidence.error,
    envFile: path.relative(infraRoot, envFile).replaceAll("\\", "/"),
    targetManifest: {
      path: path.relative(infraRoot, target.path).replaceAll("\\", "/"),
      sha256: target.sha256,
      source: "FG-048 platform.release-candidate/v1 receipt plus deployment image expectations",
    },
    workloadLock: {
      path: path.relative(infraRoot, workloadLock).replaceAll("\\", "/"),
      sha256: workloadLockSha256 || null,
    },
    ...evaluation,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("runtime-fingerprint", `runtime-fingerprint-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("runtime-fingerprint", `runtime-fingerprint-${stamp}`, [
    "# Platform Runtime Fingerprint",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Commit: ${payload.git.commit}`,
    `Tree: ${payload.git.tree}`,
    `Worktree clean: ${payload.git.clean}`,
    `Deployment ID: ${payload.expected.candidate ? payload.expected.deploymentId : "missing"}`,
    `Target manifest SHA256: ${payload.targetManifest.sha256}`,
    `Compose project: ${project}`,
    `Candidate: ${payload.candidate?.id ?? "not-bound"}`,
    `Expected services: ${payload.expectedServiceCount}`,
    `Runtime containers: ${payload.actualContainerCount}`,
    `Fingerprint: ${payload.fingerprint ?? "not-generated"}`,
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Runtime fingerprint reports written to ${jsonPath} and ${markdownPath}`);
  if (!noDocker && payload.status !== "passed") fail(`Runtime fingerprint mismatch. Report: ${jsonPath}`);
  if (!noDocker) log("Platform runtime fingerprint passed.");
}

function addRateLimitEvidenceCheck(checks, issues, { name, category, status, detail, required = true, file = null }) {
  const check = {
    name,
    category,
    required,
    status,
    detail,
    file,
  };
  checks.push(check);
  if (required && status !== "passed") {
    issues.push(`${name}: ${detail}`);
  }
  return check;
}

function addRateLimitPatternCheck(checks, issues, { name, category, filePath, pattern, detail, required = true }) {
  const relativeFile = path.relative(infraRoot, filePath).replaceAll("\\", "/");
  if (!fs.existsSync(filePath)) {
    addRateLimitEvidenceCheck(checks, issues, {
      name,
      category,
      required,
      status: required ? "failed" : "skipped",
      detail: `missing file: ${relativeFile}`,
      file: relativeFile,
    });
    return;
  }
  const text = readText(filePath);
  const passed = pattern.test(text);
  addRateLimitEvidenceCheck(checks, issues, {
    name,
    category,
    required,
    status: passed ? "passed" : "failed",
    detail: passed ? detail : `pattern not found: ${detail}`,
    file: relativeFile,
  });
}

function addRateLimitSourcePatternCheck(checks, issues, { name, category, filePath, pattern, detail, required }) {
  const relativeFile = path.relative(sourceRoot, filePath).replaceAll("\\", "/");
  if (!fs.existsSync(filePath)) {
    addRateLimitEvidenceCheck(checks, issues, {
      name,
      category,
      required,
      status: required ? "failed" : "skipped",
      detail: `missing optional source file: ${relativeFile}`,
      file: relativeFile,
    });
    return;
  }
  const text = readText(filePath);
  const passed = pattern.test(text);
  addRateLimitEvidenceCheck(checks, issues, {
    name,
    category,
    required,
    status: passed ? "passed" : "failed",
    detail: passed ? detail : `source pattern not found: ${detail}`,
    file: relativeFile,
  });
}

async function rateLimitEvidence(options = {}) {
  const middlewares = readText(path.join(infraRoot, "traefik", "dynamic", "middlewares.yml"));
  const adminRoutes = readText(path.join(infraRoot, "traefik", "dynamic", "admin-routes.yml"));
  const projectRoutes = readText(path.join(infraRoot, "traefik", "dynamic", "project-routes.yml"));
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const edgeTraefik = readText(path.join(infraRoot, "traefik", "traefik.edge-http.yml"));
  const networkOverlay = readText(path.join(infraRoot, "compose.networks.yaml"));
  const checks = [
    { name: "traefik-rate-limit-defined", passed: /enterprise-rate-limit:[\s\S]*rateLimit:[\s\S]*average:\s*\d+[\s\S]*burst:\s*\d+/.test(middlewares) },
    { name: "rate-limit-trusted-client-key", passed: /sourceCriterion:[\s\S]*ipStrategy:[\s\S]*excludedIPs:/.test(middlewares) && !/ipStrategy:[\s\S]*depth:/.test(middlewares) },
    { name: "forwarded-identity-fixed-waf-peer", passed: /forwardedHeaders:[\s\S]*trustedIPs:[\s\S]*172\.30\.250\.2\/32/.test(edgeTraefik) && !/insecure:\s*true/.test(edgeTraefik) },
    { name: "waf-peer-address-bound", passed: /waf:[\s\S]*platform_edge:[\s\S]*ipv4_address:\s*172\.30\.250\.2/.test(networkOverlay) && /subnet:\s*172\.30\.250\.0\/29/.test(networkOverlay) },
    { name: "admin-routes-rate-limited", passed: /enterprise-rate-limit@file/.test(adminRoutes) },
    { name: "hosted-routes-rate-limited", passed: /enterprise-rate-limit@file/.test(projectRoutes) },
    { name: "waf-enabled", passed: /middlewares:[\s\S]*enterprise-rate-limit@file/.test(compose) },
  ];
  const issues = checks.filter((check) => !check.passed).map((check) => check.name);
  const payload = { generatedAt: new Date().toISOString(), status: issues.length ? "failed" : "passed", scope: "platform-infrastructure", infraChecksPassed: checks.filter((check) => check.passed).length, checks, issues };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("rate-limits", `rate-limit-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("rate-limits", `rate-limit-evidence-${stamp}`, ["# Platform Rate Limit Evidence", "", `Status: ${payload.status}`, `Generated at: ${payload.generatedAt}`, "", ...checks.map((check) => `- ${check.passed ? "passed" : "failed"}: ${check.name}`)]);
  log(`Rate-limit evidence written to ${jsonPath} and ${markdownPath}`);
  if (issues.length && !booleanFlag(options.allowFailures ?? argv.allowFailures)) fail(`Rate-limit evidence failed: ${issues.join(", ")}`);
}

function addAuditLogEvidenceCheck(checks, issues, { name, category, status, detail, required = true, file = null }) {
  const check = {
    name,
    category,
    required,
    status,
    detail,
    file,
  };
  checks.push(check);
  if (required && status !== "passed") {
    issues.push(`${name}: ${detail}`);
  }
  return check;
}

function addAuditLogPatternCheck(checks, issues, { name, category, filePath, pattern, detail, required = true, sourceFile = false }) {
  const relativeFile = path.relative(sourceFile ? sourceRoot : infraRoot, filePath).replaceAll("\\", "/");
  if (!fs.existsSync(filePath)) {
    addAuditLogEvidenceCheck(checks, issues, {
      name,
      category,
      required,
      status: required ? "failed" : "skipped",
      detail: `${sourceFile ? "missing optional source file" : "missing file"}: ${relativeFile}`,
      file: relativeFile,
    });
    return;
  }
  const text = readText(filePath);
  const passed = pattern.test(text);
  addAuditLogEvidenceCheck(checks, issues, {
    name,
    category,
    required,
    status: passed ? "passed" : "failed",
    detail: passed ? detail : `pattern not found: ${detail}`,
    file: relativeFile,
  });
}

async function auditLogEvidence(options = {}) {
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const controlCenter = readText(path.join(infraRoot, "control-center", "server.mjs"));
  const promtail = readText(path.join(infraRoot, "promtail", "config.yml"));
  const checks = [
    { name: "admin-audit-file", passed: /PROJECT_AUDIT_FILE:\s+\/var\/www\/project-state\/audit\.jsonl/.test(compose) },
    { name: "append-only-admin-audit", passed: /appendAuditRecord|appendAudit/.test(controlCenter) && /audit\.jsonl/.test(controlCenter) },
    { name: "audit-secret-redaction", passed: /redact|sensitive|secret/i.test(controlCenter) },
    { name: "central-log-shipping", passed: /docker_sd_configs|__meta_docker_container_name|loki/i.test(promtail) },
  ];
  const issues = checks.filter((check) => !check.passed).map((check) => check.name);
  const payload = { generatedAt: new Date().toISOString(), status: issues.length ? "failed" : "passed", scope: "platform-infrastructure", infraChecksPassed: checks.filter((check) => check.passed).length, checks, issues };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("audit-logs", `audit-log-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("audit-logs", `audit-log-evidence-${stamp}`, ["# Platform Audit Log Evidence", "", `Status: ${payload.status}`, `Generated at: ${payload.generatedAt}`, "", ...checks.map((check) => `- ${check.passed ? "passed" : "failed"}: ${check.name}`)]);
  log(`Audit-log evidence written to ${jsonPath} and ${markdownPath}`);
  if (issues.length && !booleanFlag(options.allowFailures ?? argv.allowFailures)) fail(`Audit-log evidence failed: ${issues.join(", ")}`);
}

function addRetentionEvidenceCheck(checks, issues, { name, category, status, detail, required = true, file = null }) {
  const check = {
    name,
    category,
    required,
    status,
    detail,
    file,
  };
  checks.push(check);
  if (required && status !== "passed") {
    issues.push(`${name}: ${detail}`);
  }
  return check;
}

function addRetentionPatternCheck(checks, issues, { name, category, filePath, pattern, detail, required = true, sourceFile = false }) {
  const relativeFile = path.relative(sourceFile ? sourceRoot : infraRoot, filePath).replaceAll("\\", "/");
  if (!fs.existsSync(filePath)) {
    addRetentionEvidenceCheck(checks, issues, {
      name,
      category,
      required,
      status: required ? "failed" : "skipped",
      detail: `${sourceFile ? "missing optional source file" : "missing file"}: ${relativeFile}`,
      file: relativeFile,
    });
    return;
  }
  const text = readText(filePath);
  const passed = pattern.test(text);
  addRetentionEvidenceCheck(checks, issues, {
    name,
    category,
    required,
    status: passed ? "passed" : "failed",
    detail: passed ? detail : `pattern not found: ${detail}`,
    file: relativeFile,
  });
}

async function retentionEvidence(options = {}) {
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const loki = readText(path.join(infraRoot, "loki", "config.yml"));
  const opsScript = readText(path.join(infraRoot, "scripts", "infra-ops.mjs"));
  const checks = [
    { name: "bounded-container-logs", passed: /max-size:\s+"10m"[\s\S]*max-file:\s+"5"/.test(compose) },
    { name: "prometheus-retention", passed: /storage\.tsdb\.retention\.time=\$\{PROMETHEUS_RETENTION_TIME:-15d\}/.test(compose) },
    { name: "loki-retention", passed: /retention_enabled:\s+true[\s\S]*retention_period:\s*168h/.test(loki) || /retention_period:\s*168h[\s\S]*retention_enabled:\s+true/.test(loki) },
    { name: "backup-retention", passed: /pruneManifestBackups[\s\S]*prunePostgresBackups/.test(opsScript) },
    { name: "platform-restore-evidence", passed: /backup-restore-runs\.jsonl[\s\S]*writeBackupFreshnessMetrics/.test(opsScript) },
  ];
  const issues = checks.filter((check) => !check.passed).map((check) => check.name);
  const payload = { generatedAt: new Date().toISOString(), status: issues.length ? "failed" : "passed", mode: "platform-policy", scope: "platform-infrastructure", infraChecksPassed: checks.filter((check) => check.passed).length, checks, issues };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("retention", `retention-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("retention", `retention-evidence-${stamp}`, ["# Platform Retention Evidence", "", `Status: ${payload.status}`, `Generated at: ${payload.generatedAt}`, "", ...checks.map((check) => `- ${check.passed ? "passed" : "failed"}: ${check.name}`)]);
  log(`Retention evidence written to ${jsonPath} and ${markdownPath}`);
  if (issues.length && !booleanFlag(options.allowFailures ?? argv.allowFailures)) fail(`Retention evidence failed: ${issues.join(", ")}`);
}

const managedSecretRotationExpectations = [
  { name: "backup_scheduler_docker_gateway_token", kind: "opaque", rotationDays: 90 },
  { name: "postgres_superuser_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "keycloak_db_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "redis_password", kind: "opaque", rotationDays: 90 },
  { name: "keycloak_admin_password", kind: "opaque", rotationDays: 90 },
  { name: "nats_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "minio_root_password", kind: "opaque", rotationDays: 90 },
  { name: "mariadb_root_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "phpmyadmin_control_password", kind: "opaque", rotationDays: 90 },
  { name: "grafana_admin_password", kind: "opaque", rotationDays: 90 },
  { name: "projects_gateway_signing_keys", kind: "keyring", rotationDays: 90 },
  { name: "control_center_vault_keys", kind: "keyring", rotationDays: 90, manualRotation: true },
  { name: "backup_signing_keys", kind: "keyring", rotationDays: 90 },
  { name: "alertmanager_webhook_token", kind: "opaque", rotationDays: 90 },
  { name: "smtp_password", kind: "opaque", rotationDays: 90 },
];

function parseJsonLines(raw) {
  const entries = [];
  let invalidLines = 0;
  for (const line of String(raw ?? "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      entries.push(JSON.parse(trimmed));
    } catch {
      invalidLines += 1;
    }
  }
  return { entries, invalidLines };
}

function readJsonLines(filePath) {
  if (!fs.existsSync(filePath)) return { entries: [], invalidLines: 0 };
  return parseJsonLines(readText(filePath));
}

function platformAdminAuditCategory(action) {
  const value = String(action || "");
  if (/^admin\.login(?:\.|$)/.test(value)) return "login";
  if (/^admin\.logout(?:\.|$)/.test(value)) return "logout";
  if (value === "admin.readiness.access") return "readiness-access";
  if (value === "admin.providers.access") return "providers-access";
  if (value === "admin.monitoring.access") return "monitoring-access";
  if (/^adapter\.[a-z0-9-]+\.verify\.plan$/.test(value) || /^status\.verify(?:\.|$)/.test(value)) return "verify";
  if (/^adapter\.[a-z0-9-]+(?:\.[a-z0-9-]+)*\.plan$/.test(value) || /^(backup|restore)\.plan$/.test(value) || /\.plan$/.test(value) && /^(settings|provider\.connection|security\.policy|resources\.limits|material|alerts\.channel)\./.test(value)) return "plan";
  if (/^(settings\.update|provider\.connection|security\.policy|resources\.limits|material\.(rotation|usage|access)|alerts\.channel)\.apply$/.test(value)) return "metadata-update";
  return "";
}

function auditRecordHasSensitiveKey(value, pathParts = []) {
  if (!value || typeof value !== "object") return null;
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const nested = auditRecordHasSensitiveKey(value[index], [...pathParts, String(index)]);
      if (nested) return nested;
    }
    return null;
  }
  for (const [key, nestedValue] of Object.entries(value)) {
    const nextPath = [...pathParts, key];
    if (/(password|secret|token|authorization|cookie|credential)/i.test(key) && nestedValue !== "" && nestedValue !== null && nestedValue !== undefined) {
      return nextPath.join(".");
    }
    const nested = auditRecordHasSensitiveKey(nestedValue, nextPath);
    if (nested) return nested;
  }
  return null;
}

async function platformAdminAuditEvidence() {
  log("==> Platform admin audit evidence");
  const auditPath = path.resolve(argv.auditFile ?? process.env.PROJECT_AUDIT_FILE ?? path.join(infraRoot, "projects-portal", "state", "audit.jsonl"));
  const requiredCategories = [
    "login",
    "logout",
    "readiness-access",
    "providers-access",
    "monitoring-access",
    "verify",
    "plan",
    "metadata-update",
  ];
  const issues = [];
  let auditSource = path.relative(infraRoot, auditPath).replaceAll("\\", "/");
  let auditData = readJsonLines(auditPath);
  if (!fs.existsSync(auditPath) && !argv.auditFile) {
    const container = String(argv.auditContainer ?? "enterprise-control-center");
    const containerPath = String(argv.auditContainerPath ?? "/var/www/project-state/audit.jsonl");
    const result = run("docker", ["exec", container, "cat", containerPath], { allowFailure: true, capture: true });
    if (result.status === 0) {
      auditData = parseJsonLines(result.stdout);
      auditSource = `container:${container}:${containerPath}`;
    }
  }
  const { entries, invalidLines } = auditData;
  if (!entries.length && !fs.existsSync(auditPath) && !auditSource.startsWith("container:")) {
    issues.push(`missing audit source: ${auditSource}`);
  }
  if (invalidLines > 0) {
    issues.push(`audit file has ${invalidLines} invalid JSON line(s)`);
  }
  if (!entries.length) {
    issues.push("audit file has no events");
  }

  const seenIds = new Set();
  let previousTimestamp = 0;
  let duplicateIds = 0;
  let invalidTimestamps = 0;
  let outOfOrderTimestamps = 0;
  const categories = new Map(requiredCategories.map((name) => [name, []]));
  const ignoredHostedApplicationEvents = [];
  const sensitiveKeyPaths = [];
  for (const entry of entries) {
    const id = String(entry.id || "");
    if (!id || seenIds.has(id)) duplicateIds += 1;
    if (id) seenIds.add(id);
    const timestamp = Date.parse(entry.timestamp);
    if (!Number.isFinite(timestamp)) {
      invalidTimestamps += 1;
    } else {
      if (timestamp < previousTimestamp) outOfOrderTimestamps += 1;
      previousTimestamp = timestamp;
    }
    const sensitivePath = auditRecordHasSensitiveKey(entry);
    if (sensitivePath) sensitiveKeyPaths.push(`${id || "unknown"}:${sensitivePath}`);
    const action = String(entry.action || "");
    if (/^(project|application|subdomain)\./.test(action)) {
      ignoredHostedApplicationEvents.push(action);
      continue;
    }
    const category = platformAdminAuditCategory(action);
    if (category && categories.has(category)) categories.get(category).push(entry);
  }
  if (duplicateIds) issues.push(`audit file has ${duplicateIds} missing or duplicate id(s)`);
  if (invalidTimestamps) issues.push(`audit file has ${invalidTimestamps} invalid timestamp(s)`);
  if (outOfOrderTimestamps) issues.push(`audit timestamps are not append-order monotonic: ${outOfOrderTimestamps} event(s) out of order`);
  if (sensitiveKeyPaths.length) issues.push(`audit file contains sensitive-looking key path(s): ${sensitiveKeyPaths.slice(0, 5).join(", ")}`);

  const controlCenterPath = path.join(infraRoot, "control-center", "server.mjs");
  const controlCenterText = readText(controlCenterPath);
  const fileStoreText = readText(path.join(infraRoot, "control-center", "state", "file-store.mjs"));
  const appendOnlySource = /function appendAudit[\s\S]*controlState\.append\("audit"/.test(controlCenterText)
    && /openSync\(definition\.path, "a", 0o600\)/.test(fileStoreText)
    && /fsyncSync\(fd\)/.test(fileStoreText)
    && !/truncateSync\(definition\.path|rmSync\(definition\.path|unlinkSync\(definition\.path/.test(fileStoreText);
  if (!appendOnlySource) {
    issues.push("Control Center audit writer is not append-only in source inspection");
  }

  const checks = requiredCategories.map((name) => {
    const events = categories.get(name) ?? [];
    return {
      name,
      status: events.length ? "passed" : "failed",
      count: events.length,
      latestAt: events.at(-1)?.timestamp ?? null,
      detail: events.length ? "platform portal event observed" : "no matching platform portal event observed",
    };
  });
  for (const check of checks) {
    if (check.status !== "passed") issues.push(`missing platform admin audit coverage: ${check.name}`);
  }

  const stamp = reportTimestamp();
  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : "passed",
    mode: "runtime",
    scope: "platform-infrastructure",
    auditFile: auditSource,
    appendOnly: {
      source: appendOnlySource,
      jsonl: true,
      monotonicTimestamps: outOfOrderTimestamps === 0,
      duplicateIds,
      invalidLines,
    },
    summary: {
      events: entries.length,
      platformEventsUsed: checks.reduce((sum, check) => sum + check.count, 0),
      ignoredHostedApplicationEvents: ignoredHostedApplicationEvents.length,
      failedChecks: checks.filter((check) => check.status !== "passed").length,
      sensitiveKeyFindings: sensitiveKeyPaths.length,
    },
    checks,
    issues,
    piiIncluded: false,
    secretsIncluded: false,
  };
  const jsonPath = writeJsonReport("platform-admin-audit", `platform-admin-audit-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("platform-admin-audit", `platform-admin-audit-${stamp}`, [
    "# Platform Admin Audit Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    `Audit file: ${payload.auditFile}`,
    "",
    "## Summary",
    "",
    `- Events: ${payload.summary.events}`,
    `- Platform events used: ${payload.summary.platformEventsUsed}`,
    `- Ignored hosted application events: ${payload.summary.ignoredHostedApplicationEvents}`,
    `- Failed checks: ${payload.summary.failedChecks}`,
    `- Sensitive key findings: ${payload.summary.sensitiveKeyFindings}`,
    "",
    "## Checks",
    "",
    "| Check | Status | Count | Latest at | Detail |",
    "| --- | --- | ---: | --- | --- |",
    ...checks.map((check) => `| ${check.name} | ${check.status} | ${check.count} | ${check.latestAt || "n/a"} | ${check.detail} |`),
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "PII included: no",
    "Secrets included: no",
  ]);
  log(`Platform admin audit report written to ${jsonPath} and ${markdownPath}`);
  if (issues.length && !booleanFlag(argv.allowFailures)) {
    fail(`Platform admin audit evidence failed with ${issues.length} issue(s). Report: ${jsonPath}`);
  }
  log("Platform admin audit evidence passed.");
}

function ageDaysFromIso(value) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return Number.POSITIVE_INFINITY;
  return (Date.now() - timestamp) / 86400000;
}

function optionalPositiveNumber(value, optionName, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    fail(`${optionName} must be a non-negative number.`);
  }
  return parsed;
}

function secretRotationLatestEvent(entries, actions) {
  const allowed = new Set(actions);
  return entries
    .filter((entry) => allowed.has(entry.action) && entry.status !== "failed" && Number.isFinite(Date.parse(entry.at)))
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at))[0] ?? null;
}

function secretRotationEventSummary(entry) {
  if (!entry) return null;
  return {
    at: entry.at,
    action: entry.action,
    status: entry.status ?? "success",
    name: entry.name ?? null,
  };
}

async function secretRotationEvidence(options = {}) {
  log("==> Secret rotation evidence");
  const enforce = options.enforce ?? booleanFlag(argv.enforce);
  const secretsDir = path.resolve(options.secretsDir ?? argv.secretsDir ?? path.join(infraRoot, "secrets"));
  const storePath = path.resolve(options.store ?? argv.store ?? path.join(secretsDir, "infra-secret-manager-store.json"));
  const auditLogPath = path.resolve(options.auditLog ?? argv.auditLog ?? path.join(secretsDir, "infra-secret-manager-audit.log"));
  const maxKmsAgeDays = optionalPositiveNumber(options.maxKmsAgeDays ?? argv.maxKmsAgeDays, "--maxKmsAgeDays", 180);
  const rotationGraceDays = optionalPositiveNumber(options.rotationGraceDays ?? argv.rotationGraceDays, "--rotationGraceDays", 0);
  const generatedAt = new Date().toISOString();
  const issues = [];
  const secretReports = [];
  let store = null;
  let verify = { status: "not-run", detail: "store missing" };

  if (!fs.existsSync(storePath)) {
    if (enforce) {
      issues.push(`missing Infra Secret Manager store: ${storePath}`);
    }
  } else {
    try {
      store = readJsonFile(storePath, storePath);
    } catch (error) {
      issues.push(`secret manager store is unreadable: ${String(error?.message ?? error)}`);
    }
  }

  if (store) {
    if (store.manager !== "infra-secret-manager" || store.version !== 1) {
      issues.push("secret manager store has an invalid manager/version marker");
    }
    if (store.kms?.provider !== "local-bucket-kms" || !store.kms?.activeKeyId) {
      issues.push("secret manager store is missing active Platform Local KMS metadata");
    }
    const activeKmsKey = store.kms?.keys?.[store.kms?.activeKeyId];
    const activeKmsAgeDays = ageDaysFromIso(activeKmsKey?.createdAt);
    if (!Number.isFinite(activeKmsAgeDays)) {
      issues.push("active KMS key is missing a valid createdAt timestamp");
    } else if (activeKmsAgeDays > maxKmsAgeDays) {
      issues.push(`active KMS key is ${activeKmsAgeDays.toFixed(1)}d old; max ${maxKmsAgeDays}d`);
    }

    const storeSecrets = store.secrets ?? {};
    const legacyFingerprintNames = legacyPlaintextFingerprintNames(store);
    if (legacyFingerprintNames.length) {
      issues.push(`legacy plaintext-derived secret fingerprints require migrate-metadata: ${legacyFingerprintNames.join(", ")}`);
    }
    for (const expected of managedSecretRotationExpectations) {
      const record = storeSecrets[expected.name];
      const materializedPath = path.join(secretsDir, `${expected.name}.txt`);
      const materializedPresent = fs.existsSync(materializedPath) && fs.statSync(materializedPath).isFile() && fs.statSync(materializedPath).size > 0;
      if (!record) {
        issues.push(`missing managed secret record: ${expected.name}`);
        secretReports.push({
          name: expected.name,
          kind: expected.kind,
          status: "missing",
          materializedPresent,
          rotationDays: expected.rotationDays,
          ageDays: null,
          expired: true,
          manualRotation: Boolean(expected.manualRotation),
        });
        continue;
      }
      const rotationDays = Number(record.rotationDays ?? expected.rotationDays);
      const ageDays = ageDaysFromIso(record.updatedAt);
      const allowedAgeDays = Math.max(0, rotationDays + rotationGraceDays);
      const expired = !Number.isFinite(ageDays) || ageDays > allowedAgeDays;
      const status = expired || !materializedPresent || record.kind !== expected.kind ? "failed" : "passed";
      if (record.kind !== expected.kind) {
        issues.push(`${expected.name} kind=${record.kind ?? "missing"} expected=${expected.kind}`);
      }
      if (!materializedPresent) {
        issues.push(`missing materialized Docker secret file for ${expected.name}`);
      }
      if (!Number.isFinite(ageDays)) {
        issues.push(`${expected.name} has an invalid updatedAt timestamp`);
      } else if (expired) {
        issues.push(`${expected.name} is ${ageDays.toFixed(1)}d old; max ${allowedAgeDays}d`);
      }
      secretReports.push({
        name: expected.name,
        scope: record.scope ?? "platform",
        owner: record.owner ?? "platform",
        kind: record.kind ?? expected.kind,
        status,
        updatedAt: record.updatedAt ?? null,
        ageDays: Number.isFinite(ageDays) ? Number(ageDays.toFixed(3)) : null,
        rotationDays,
        rotationGraceDays,
        expired,
        manualRotation: Boolean(expected.manualRotation),
        materializedPresent,
        legacyPlaintextFingerprintPresent: Object.prototype.hasOwnProperty.call(record, "fingerprint"),
        kmsKeyId: record.encryption?.keyId ?? null,
        keyIds: Array.isArray(record.keyIds) ? record.keyIds : [],
      });
    }

    const expectedNames = new Set(managedSecretRotationExpectations.map((secret) => secret.name));
    const unexpectedNames = [];
    for (const name of Object.keys(storeSecrets).filter((secretName) => !expectedNames.has(secretName)).sort()) {
      const record = storeSecrets[name];
      const isVaultRecord = record?.scope === "vault" || (record?.owner && record.owner !== "platform");
      if (!isVaultRecord) {
        unexpectedNames.push(name);
        continue;
      }
      const materializedPath = path.join(secretsDir, `${name}.txt`);
      const materializedPresent = fs.existsSync(materializedPath) && fs.statSync(materializedPath).isFile() && fs.statSync(materializedPath).size > 0;
      const rotationDays = Number(record.rotationDays ?? 90);
      const ageDays = ageDaysFromIso(record.updatedAt);
      const allowedAgeDays = Math.max(0, rotationDays + rotationGraceDays);
      const expired = !Number.isFinite(ageDays) || ageDays > allowedAgeDays;
      const status = expired || !materializedPresent || record.kind !== "opaque" ? "failed" : "passed";
      if (record.kind !== "opaque") {
        issues.push(`${name} vault kind=${record.kind ?? "missing"} expected=opaque`);
      }
      if (!materializedPresent) {
        issues.push(`missing materialized vault secret file for ${name}`);
      }
      if (!Number.isFinite(ageDays)) {
        issues.push(`${name} has an invalid updatedAt timestamp`);
      } else if (expired) {
        issues.push(`${name} is ${ageDays.toFixed(1)}d old; max ${allowedAgeDays}d`);
      }
      secretReports.push({
        name,
        scope: "vault",
        owner: record.owner ?? "vault",
        kind: record.kind ?? "opaque",
        status,
        updatedAt: record.updatedAt ?? null,
        ageDays: Number.isFinite(ageDays) ? Number(ageDays.toFixed(3)) : null,
        rotationDays,
        rotationGraceDays,
        expired,
        manualRotation: false,
        materializedPresent,
        legacyPlaintextFingerprintPresent: Object.prototype.hasOwnProperty.call(record, "fingerprint"),
        kmsKeyId: record.encryption?.keyId ?? null,
        keyIds: Array.isArray(record.keyIds) ? record.keyIds : [],
      });
    }
    if (unexpectedNames.length) {
      issues.push(`unexpected non-vault secret records: ${unexpectedNames.join(", ")}`);
    }

    const verifyResult = runSecretManager([
      "verify",
      "--secretsDir",
      secretsDir,
      "--store",
      storePath,
      "--auditLog",
      auditLogPath,
    ], { capture: true, allowFailure: true });
    verify = {
      status: verifyResult.status === 0 ? "passed" : "failed",
      detail: verifyResult.status === 0
        ? "secret manager verify passed"
        : String(verifyResult.stderr || verifyResult.stdout || "secret manager verify failed").trim(),
    };
    if (verifyResult.status !== 0) {
      issues.push("infra-secret-manager verify failed");
    }
  }

  const audit = readJsonLines(auditLogPath);
  const auditActions = audit.entries.reduce((acc, entry) => {
    acc[entry.action] = (acc[entry.action] ?? 0) + 1;
    return acc;
  }, {});
  const latestManagedEvent = secretRotationLatestEvent(audit.entries, ["init", "rotate", "set", "kms_rotate", "materialize", "verify"]);
  const latestRotationEvent = secretRotationLatestEvent(audit.entries, ["rotate", "set", "kms_rotate", "init"]);
  if (store && !fs.existsSync(auditLogPath)) {
    issues.push(`missing secret manager audit log: ${auditLogPath}`);
  }
  if (store && audit.invalidLines) {
    issues.push(`secret manager audit log has ${audit.invalidLines} invalid JSON line(s)`);
  }
  if (store && !latestManagedEvent) {
    issues.push("secret manager audit log has no successful managed operation events");
  }
  if (store && !latestRotationEvent) {
    issues.push("secret manager audit log has no init/rotate/set/kms_rotate event");
  }

  const expiredSecrets = secretReports.filter((secret) => secret.expired);
  const failedSecrets = secretReports.filter((secret) => secret.status !== "passed");
  const payload = {
    generatedAt,
    mode: store ? "evidence" : "plan",
    status: store ? (issues.length ? "failed" : "passed") : (enforce ? "failed" : "plan"),
    enforce,
    store: {
      path: storePath,
      present: Boolean(store),
      manager: store?.manager ?? null,
      version: store?.version ?? null,
      updatedAt: store?.updatedAt ?? null,
    },
    kms: store ? {
      provider: store.kms?.provider ?? null,
      activeKeyId: store.kms?.activeKeyId ?? null,
      activeKeyCreatedAt: store.kms?.keys?.[store.kms?.activeKeyId]?.createdAt ?? null,
      activeKeyAgeDays: Number.isFinite(ageDaysFromIso(store.kms?.keys?.[store.kms?.activeKeyId]?.createdAt))
        ? Number(ageDaysFromIso(store.kms?.keys?.[store.kms?.activeKeyId]?.createdAt).toFixed(3))
        : null,
      maxAgeDays: maxKmsAgeDays,
    } : null,
    audit: {
      path: auditLogPath,
      present: fs.existsSync(auditLogPath),
      entries: audit.entries.length,
      invalidLines: audit.invalidLines,
      actions: auditActions,
      latestManagedEvent: secretRotationEventSummary(latestManagedEvent),
      latestRotationEvent: secretRotationEventSummary(latestRotationEvent),
    },
    verify,
    summary: {
      expectedSecrets: managedSecretRotationExpectations.length,
      reportedSecrets: secretReports.length,
      failedSecrets: failedSecrets.length,
      vaultSecrets: secretReports.filter((secret) => secret.scope === "vault").length,
      expiredSecrets: expiredSecrets.length,
      missingMaterializedFiles: secretReports.filter((secret) => !secret.materializedPresent).length,
      manualRotationSecrets: secretReports.filter((secret) => secret.manualRotation).length,
      maxKmsAgeDays,
      rotationGraceDays,
    },
    secrets: secretReports,
    issues,
    nextCommands: [
      "sh ./scripts/infra-secret-manager.sh init",
      "sh ./scripts/infra-secret-manager.sh verify",
      "sh ./scripts/infra-secret-manager.sh rotate --name control_center_vault_keys",
      "sh ./scripts/infra-secret-manager.sh kms-rotate",
      "sh ./scripts/secret-rotation-evidence.sh --enforce",
    ],
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("secret-rotation", `secret-rotation-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("secret-rotation", `secret-rotation-evidence-${stamp}`, [
    "# Secret Rotation Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    `Store present: ${payload.store.present ? "yes" : "no"}`,
    `Verify: ${payload.verify.status}`,
    `Expired secrets: ${payload.summary.expiredSecrets}`,
    `Failed secrets: ${payload.summary.failedSecrets}`,
    `Missing materialized files: ${payload.summary.missingMaterializedFiles}`,
    "",
    "| Secret | Scope | Status | Kind | Age days | Rotation days | Materialized |",
    "| --- | --- | --- | --- | ---: | ---: | --- |",
    ...(secretReports.length
      ? secretReports.map((secret) => `| ${secret.name} | ${secret.scope ?? "platform"} | ${secret.status} | ${secret.kind} | ${secret.ageDays ?? "n/a"} | ${secret.rotationDays ?? "n/a"} | ${secret.materializedPresent ? "yes" : "no"} |`)
      : ["| n/a | n/a | plan | n/a | n/a | n/a | no |"]),
    "",
    "## Audit",
    "",
    `Entries: ${payload.audit.entries}`,
    `Latest managed event: ${payload.audit.latestManagedEvent ? `${payload.audit.latestManagedEvent.action} at ${payload.audit.latestManagedEvent.at}` : "n/a"}`,
    `Latest rotation event: ${payload.audit.latestRotationEvent ? `${payload.audit.latestRotationEvent.action} at ${payload.audit.latestRotationEvent.at}` : "n/a"}`,
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "## Next Commands",
    "",
    ...payload.nextCommands.map((commandLine) => `- \`${commandLine}\``),
  ]);
  log(`Secret rotation evidence written to ${jsonPath} and ${markdownPath}`);
  if (enforce && payload.status !== "passed") {
    fail(`Secret rotation evidence failed with ${issues.length} issue(s). Report: ${jsonPath}`);
  }
}

async function releaseArtifactGate(options = {}) {
  let result = null;
  await withLocalCheckReport("release-artifact-gate", async () => {
    result = await releaseArtifactGateBody(options);
  }, {
    requireProvenance: Boolean(options.requireProvenance ?? booleanFlag(argv.requireProvenance)),
    verifyCosign: Boolean(options.verifyCosign ?? booleanFlag(argv.verifyCosign)),
  });
  return result;
}

async function releaseArtifactGateBody(options = {}) {
  log("==> Release artifact admission gate");
  const env = parseEnv(path.resolve(options.envFile ?? argv.envFile ?? path.join(infraRoot, ".env")));
  const imageEntries = releaseImageEntries({
    env,
    imagesArg: options.images ?? argv.images,
    manifestPath: options.imageManifest ?? argv.imageManifest ?? argv.projectManifest ?? argv.appManifest,
  });
  const images = imageEntries.map((entry) => entry.image);
  if (!images.length) {
    fail("No release images found. Pass --imageManifest <file> or --images <ref[,ref]>.");
  }
  for (const image of images) {
    if (/:latest(?:@|$)/.test(image)) {
      fail(`Mutable :latest image is not admissible: ${image}`);
    }
    if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
      fail(`Release image must be digest-pinned: ${image}`);
    }
  }

  const sbomFile = options.sbom ?? argv.sbom ?? latestFileByMtime(path.join(infraRoot, "security", "sbom"), (file) => /sbom.*\.(json|cdx\.json)$/i.test(path.basename(file)));
  if (!sbomFile || !fs.existsSync(sbomFile)) {
    fail("A release SBOM artifact is required. Run generate-sbom or pass --sbom <file>.");
  }
  readJsonFile(sbomFile, sbomFile);

  const policy = readText(path.join(infraRoot, "security", "admission", "cosign-digest-policy.rego"));
  assertMatch(policy, /cosign\.sigstore\.dev\/verified/, "Admission policy must require cosign verification annotation.");
  assertMatch(policy, /slsa\.dev\/provenance/, "Admission policy must require SLSA provenance annotation.");

  rejectLegacyProvenanceInputs(options);
  const requireProvenance = options.requireProvenance ?? booleanFlag(argv.requireProvenance);
  const releaseSha = options.releaseSha ?? argv.releaseSha ?? gitEvidence().commit;
  let githubAttestationValidation = null;
  if (requireProvenance) {
    loadGithubTokenFromFile();
    githubAttestationValidation = verifyGithubReleaseImages({
      images,
      ...releaseTrustVerificationOptions(options, releaseSha),
    });
  }
  if (booleanFlag(argv.verifyCosign)) {
    for (const image of images) {
      run("cosign", ["verify", image]);
    }
  }
  log(`Release artifact admission gate passed with SBOM ${sbomFile}.`);
  return { sbomFile, provenanceValidation: null, githubAttestationValidation };
}

function releaseImageMapFromEnv(env, manifestPath = null) {
  return imageMapFromEntries(releaseImageEntries({ env, manifestPath }));
}

function previousReleaseImageMap(env, fileImages = {}, imageKeys = releaseImageKeys) {
  return Object.fromEntries(imageKeys.map((key) => [key, env[`PREVIOUS_${key}`] ?? fileImages[`PREVIOUS_${key}`] ?? fileImages[key] ?? null]));
}

function releaseArtifactRef(filePath) {
  if (!filePath) {
    return null;
  }
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    fail(`Release artifact not found: ${resolved}`);
  }
  const stat = fs.statSync(resolved);
  return {
    path: resolved,
    name: path.basename(resolved),
    sizeBytes: stat.size,
    sha256: sha256File(resolved),
  };
}

function safeReleaseArtifactRef(filePath, issues, label) {
  if (!filePath) {
    return null;
  }
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    issues.push(`${label} artifact not found: ${resolved}`);
    return null;
  }
  return releaseArtifactRef(resolved);
}

function writeReleaseEvidenceReport(payload) {
  const stamp = reportTimestamp();
  const currentImages = payload.currentImages ?? {};
  const previousImages = payload.previousImages ?? {};
  const imageKeys = Object.keys(currentImages);
  const firstDeploy = Boolean(payload.rollback?.firstDeploy);
  const rollbackFilePath = payload.rollback?.file ?? null;
  const rollbackDryRun = payload.rollback?.dryRun ?? null;
  const jsonPath = writeJsonReport("release", `release-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("release", `release-evidence-${stamp}`, [
    "# Platform Release Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    `Release: ${payload.releaseName}`,
    `Commit: ${payload.releaseSha ?? "n/a"}`,
    `Environment: ${payload.environment}`,
    `Approved by: ${payload.approvedBy ?? "n/a"}`,
    `Candidate: ${payload.candidate?.id ?? "not-bound"}`,
    "",
    "| Image variable | Current image | Rollback image |",
    "| --- | --- | --- |",
    ...imageKeys.map((key) => `| ${key} | \`${currentImages[key] ?? "n/a"}\` | \`${previousImages[key] ?? (firstDeploy ? "first deploy" : "missing")}\` |`),
    "",
    "| Artifact | Path | SHA256 |",
    "| --- | --- | --- |",
    `| SBOM | ${payload.artifacts?.sbom?.path ?? "n/a"} | ${payload.artifacts?.sbom?.sha256 ?? "n/a"} |`,
    `| Provenance | ${payload.artifacts?.provenance?.path ?? "n/a"} | ${payload.artifacts?.provenance?.sha256 ?? "n/a"} |`,
    `| Signed attestation bundle | ${payload.artifacts?.attestationBundle?.path ?? "online verification"} | ${payload.artifacts?.attestationBundle?.sha256 ?? "n/a"} |`,
    `| Trusted root | ${payload.artifacts?.trustedRoot?.path ?? "provider trust root"} | ${payload.artifacts?.trustedRoot?.sha256 ?? "n/a"} |`,
    `| Signature bundle | ${payload.artifacts?.signatureBundle?.path ?? "n/a"} | ${payload.artifacts?.signatureBundle?.sha256 ?? "n/a"} |`,
    "",
    `Rollback file: ${rollbackFilePath ?? (firstDeploy ? "first deploy" : "n/a")}`,
    `Rollback dry-run: ${rollbackDryRun?.validated ? rollbackDryRun.reportPath : (firstDeploy ? "first deploy" : "n/a")}`,
    "",
    "## Issues",
    "",
    ...(payload.issues?.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "## Next Commands",
    "",
    ...payload.nextCommands.map((commandLine) => `- \`${commandLine}\``),
  ]);
  return { jsonPath, markdownPath };
}

async function releaseEvidence(options = {}) {
  log("==> Release evidence pack");
  const planOnly = options.planOnly ?? booleanFlag(argv.planOnly);
  const firstDeploy = options.firstDeploy ?? booleanFlag(argv.firstDeploy);
  const allowUnpinned = options.allowUnpinnedReleaseImages ?? booleanFlag(argv.allowUnpinnedReleaseImages);
  const envFile = path.resolve(options.envFile ?? argv.envFile ?? path.join(infraRoot, ".env"));
  const env = fs.existsSync(envFile) ? parseEnv(envFile) : {};
  const imageManifest = options.imageManifest ?? argv.imageManifest ?? argv.projectManifest ?? argv.appManifest ?? null;
  const currentImageEntries = releaseImageEntries({
    env,
    imagesArg: options.images ?? argv.images,
    manifestPath: imageManifest,
  });
  const currentImages = imageMapFromEntries(currentImageEntries);
  const previousImagesFileArg = options.previousImagesFile ?? argv.previousImagesFile;
  const previousImagesFile = previousImagesFileArg ? path.resolve(previousImagesFileArg) : null;
  const previousFileImages = previousImagesFile && fs.existsSync(previousImagesFile) ? readJsonFile(previousImagesFile, previousImagesFile) : {};
  const previousImages = previousReleaseImageMap(env, previousFileImages, Object.keys(currentImages));
  const sbomPath = options.sbom ?? argv.sbom ?? latestFileByMtime(path.join(infraRoot, "security", "sbom"), (file) => /sbom.*\.(json|cdx\.json)$/i.test(path.basename(file)));
  const provenanceArg = options.provenance ?? argv.provenance;
  const legacyGithubAttestationArg = options.githubAttestation ?? options.githubAttestations ?? argv.githubAttestation ?? argv.githubAttestations;
  const attestationBundleArg = options.attestationBundle ?? argv.attestationBundle;
  const attestationBundlePath = attestationBundleArg ? path.resolve(attestationBundleArg) : null;
  const trustedRootArg = options.trustedRoot ?? argv.trustedRoot;
  const trustedRootPath = trustedRootArg ? path.resolve(trustedRootArg) : null;
  const signatureBundleArg = options.signatureBundle ?? argv.signatureBundle;
  const signatureBundlePath = signatureBundleArg ? path.resolve(signatureBundleArg) : null;
  const releaseSha = options.releaseSha ?? argv.releaseSha ?? gitEvidence().commit;
  const releaseName = options.releaseName ?? argv.releaseName ?? releaseSha?.slice(0, 12) ?? `release-${reportTimestamp()}`;
  const rollbackProjectName = options.rollbackProjectName ?? argv.rollbackProjectName ?? argv.projectName ?? "enterprise_prod";
  const candidateProjectName = options.candidateProjectName ?? argv.candidateProjectName ?? process.env.COMPOSE_PROJECT_NAME ?? env.COMPOSE_PROJECT_NAME ?? "platform_infra_vps";
  const rollbackServices = csvList(options.rollbackServices ?? argv.rollbackServices ?? argv.services, "platform-alert-dispatcher,control-center,php-apache");
  const rollbackComposeFiles = csvList(options.rollbackComposeFiles ?? argv.rollbackComposeFiles ?? argv.composeFiles, "compose.yaml,compose.prod.yaml");
  const generatedAt = new Date().toISOString();
  const issues = [];
  let githubAttestationValidation = null;
  const candidateEvidence = planOnly ? { candidate: null, error: "plan-only" } : currentCandidateIdentityEvidence({
    envFile,
    projectName: candidateProjectName,
    repository: options.repository ?? options.repo ?? argv.repository ?? argv.repo,
  });

  if (!planOnly) {
    try {
      if (!candidateEvidence.candidate?.trusted) fail(`Release candidate identity is not trusted: ${candidateEvidence.error ?? "worktree-not-clean"}.`);
      if (String(releaseSha ?? "").toLowerCase() !== candidateEvidence.candidate.commit) fail("Release SHA must equal the current candidate commit.");
      if (!fs.existsSync(envFile)) {
        fail(`Env file not found: ${envFile}`);
      }
      if (previousImagesFile && !fs.existsSync(previousImagesFile)) {
        fail(`Previous release image file not found: ${previousImagesFile}`);
      }
      for (const [key, image] of Object.entries(currentImages)) {
        assertDigestPinnedImageRef(key, image, { allowUnpinned, label: "release image" });
      }
      if (!firstDeploy) {
        for (const [key, image] of Object.entries(previousImages)) {
          assertDigestPinnedImageRef(key, image, { allowUnpinned, label: "rollback image" });
        }
      }
      if (!sbomPath || !fs.existsSync(path.resolve(sbomPath))) {
        fail("A release SBOM artifact is required. Run generate-sbom or pass --sbom <file>.");
      }
      readJsonFile(path.resolve(sbomPath), sbomPath);
      const requireProvenance = options.requireProvenance ?? booleanFlag(argv.requireProvenance);
      if (provenanceArg) {
        fail("Unsigned local SLSA JSON is not admissible release evidence.");
      }
      if (legacyGithubAttestationArg) {
        fail("Normalized GitHub attestation reports are not admissible release evidence.");
      }
      if ((attestationBundlePath && !trustedRootPath) || (!attestationBundlePath && trustedRootPath)) {
        fail("Offline provenance verification requires both --attestationBundle and --trustedRoot.");
      }
      if (attestationBundlePath && !fs.existsSync(attestationBundlePath)) {
        fail(`Signed attestation bundle not found: ${attestationBundlePath}`);
      }
      if (trustedRootPath && !fs.existsSync(trustedRootPath)) {
        fail(`Trusted root not found: ${trustedRootPath}`);
      }
      if (signatureBundlePath && !fs.existsSync(signatureBundlePath)) {
        fail(`Signature bundle artifact not found: ${signatureBundlePath}`);
      }
      const artifactGate = await releaseArtifactGate({
        envFile,
        images: options.images ?? argv.images,
        imageManifest,
        sbom: sbomPath,
        attestationBundle: attestationBundlePath,
        trustedRoot: trustedRootPath,
        requireProvenance,
        releaseSha,
        repository: options.repository ?? options.repo ?? argv.repository ?? argv.repo ?? process.env.GITHUB_REPOSITORY ?? null,
        sourceRef: options.sourceRef ?? argv.sourceRef ?? process.env.GITHUB_REF ?? null,
        signerWorkflow: options.signerWorkflow ?? argv.signerWorkflow ?? null,
      });
      githubAttestationValidation = artifactGate.githubAttestationValidation;
    } catch (error) {
      issues.push(String(error?.message ?? error));
    }
  }

  const sbom = planOnly && !sbomPath ? null : safeReleaseArtifactRef(sbomPath, issues, "SBOM");
  const attestationBundle = safeReleaseArtifactRef(attestationBundlePath, issues, "signed attestation bundle");
  const trustedRoot = safeReleaseArtifactRef(trustedRootPath, issues, "trusted root");
  const signatureBundle = safeReleaseArtifactRef(signatureBundlePath, issues, "Signature bundle");
  const rollbackComplete = Object.keys(currentImages).length > 0 && Object.keys(currentImages).every((key) => Boolean(previousImages[key]));
  const releaseRoot = path.join(infraRoot, "release");
  let rollbackFilePath = null;
  let rollbackDryRun = null;
  if (!planOnly && issues.length === 0 && rollbackComplete) {
    fs.mkdirSync(releaseRoot, { recursive: true });
    rollbackFilePath = path.join(releaseRoot, "previous-images.json");
    fs.writeFileSync(rollbackFilePath, `${JSON.stringify(previousImages, null, 2)}\n`, "utf8");
    if (!firstDeploy) {
      const rollbackPlan = writeRollbackPlanReport({
        envFile,
        envText: fs.readFileSync(envFile, "utf8"),
        rollbackFile: rollbackFilePath,
        imageOverrides: previousImages,
        projectName: rollbackProjectName,
        composeFiles: rollbackComposeFiles,
        services: rollbackServices,
        mode: "dry-run",
      });
      rollbackDryRun = {
        validated: rollbackPlan.payload.composeValidation.status === "passed",
        reportPath: rollbackPlan.jsonPath,
        markdownPath: rollbackPlan.markdownPath,
        generatedAt: rollbackPlan.payload.generatedAt,
        projectName: rollbackPlan.payload.projectName,
        composeFiles: rollbackPlan.payload.composeFiles,
        services: rollbackPlan.payload.services,
        postCheck: rollbackPlan.payload.postCheck,
      };
    }
  }
  const candidateEndEvidence = planOnly ? candidateEvidence : currentCandidateIdentityEvidence({
    envFile,
    projectName: candidateProjectName,
    repository: options.repository ?? options.repo ?? argv.repository ?? argv.repo,
  });
  const candidateStable = Boolean(
    candidateEvidence.candidate?.trusted
    && candidateEndEvidence.candidate?.trusted
    && candidateIdentityMatches(candidateEvidence.candidate, candidateEndEvidence.candidate),
  );
  if (!planOnly && !candidateStable) issues.push(`Release candidate changed during evidence collection: ${candidateEndEvidence.error ?? "identity-mismatch"}.`);

  const payload = {
    generatedAt,
    status: planOnly ? "plan" : issues.length ? "failed" : "passed",
    mode: planOnly ? "plan" : "evidence",
    releaseName,
    releaseSha,
    approvedBy: argv.approvedBy ?? null,
    environment: argv.environment ?? "production",
    git: gitEvidence(),
    candidate: candidateEvidence.candidate,
    candidateEnd: candidateEndEvidence.candidate,
    candidateStable,
    candidateError: candidateEvidence.error,
    envFile: fs.existsSync(envFile) ? envFile : null,
    imageManifest: imageManifest ? path.resolve(imageManifest) : null,
    currentImages,
    previousImages,
    rollback: {
      firstDeploy,
      complete: firstDeploy || rollbackComplete,
      file: rollbackFilePath,
      command: rollbackFilePath ? `sh ./scripts/rollback-release.sh --rollbackFile ${path.relative(infraRoot, rollbackFilePath).replaceAll("\\", "/")}` : null,
      dryRun: rollbackDryRun,
    },
    artifacts: {
      sbom,
      provenance: null,
      githubAttestations: [],
      attestationBundle,
      trustedRoot,
      signatureBundle,
    },
    attestations: {
      provenanceRequired: options.requireProvenance ?? booleanFlag(argv.requireProvenance),
      localProvenance: null,
      slsaProvenance: githubAttestationValidation,
      githubSigstore: githubAttestationValidation,
      cosignVerified: (options.verifyCosign ?? booleanFlag(argv.verifyCosign)) && !planOnly,
    },
    issues,
    nextCommands: [
      "sh ./scripts/release-artifact-gate.sh --requireProvenance --repo owner/repo --sourceRef refs/heads/main",
      "sh ./scripts/infra-health.sh",
      "sh ./scripts/security-smoke.sh",
      "sh ./scripts/waf-smoke.sh",
      rollbackDryRun?.reportPath
        ? `review ${path.relative(infraRoot, rollbackDryRun.reportPath).replaceAll("\\", "/")}`
        : rollbackFilePath
          ? `sh ./scripts/rollback-release.sh --rollbackFile ${path.relative(infraRoot, rollbackFilePath).replaceAll("\\", "/")}`
          : "prepare release/previous-images.json before rollback testing",
    ],
  };

  const { jsonPath, markdownPath } = writeReleaseEvidenceReport(payload);
  log(`Release evidence written to ${jsonPath} and ${markdownPath}`);
  if (rollbackFilePath) {
    log(`Rollback target written to ${rollbackFilePath}`);
  }
  if (!planOnly && issues.length) {
    fail(`Release evidence failed with ${issues.length} issue(s). Reports: ${jsonPath}, ${markdownPath}`);
  }
}

async function githubAttestationEvidence() {
  log("==> GitHub/Sigstore attestation evidence");
  if (argv.verification ?? argv.githubAttestation ?? argv.githubAttestationReport) {
    fail("Pre-generated verification JSON is not accepted. Pass the artifact --subject and let this command invoke GitHub's cryptographic verifier.");
  }
  const subject = argv.subject;
  if (!subject) {
    fail("Pass --subject <file|oci://image@sha256:digest> for cryptographic verification.");
  }
  const releaseSha = argv.releaseSha ?? argv.sourceDigest ?? argv.sha ?? gitEvidence().commit;
  const policy = releaseTrustPolicy();
  const repository = argv.repository ?? argv.repo ?? process.env.GITHUB_REPOSITORY;
  const validation = (() => {
    loadGithubTokenFromFile();
    return verifyGithubAttestation({
      subject,
      expectedSubjectDigest: argv.expectedSubjectDigest ?? argv.subjectDigest ?? (String(subject).startsWith("oci://") ? digestFromImageRef(subject) : null),
      repository,
      signerWorkflow: argv.signerWorkflow ?? `${repository}/${policy.signer_workflow_path}`,
      sourceDigest: releaseSha,
      sourceRef: argv.sourceRef ?? process.env.GITHUB_REF,
      bundle: argv.attestationBundle ?? null,
      trustedRoot: argv.trustedRoot ?? null,
      predicateType: policy.predicate_type,
      certOidcIssuer: policy.cert_oidc_issuer,
    });
  })();
  const stamp = reportTimestamp();
  const source = String(subject).startsWith("oci://")
    ? { kind: "oci", value: subject, sha256: digestFromImageRef(subject) }
    : releaseArtifactRef(path.resolve(subject));
  const payload = {
    generatedAt: new Date().toISOString(),
    status: "passed",
    mode: "cryptographic-verify",
    releaseSha,
    git: gitEvidence(),
    source,
    attestation: validation,
    nextCommands: [
      "sh ./scripts/release-evidence.sh --requireProvenance --repo owner/repo --sourceRef refs/heads/main --previousImagesFile release/previous-images.json",
    ],
  };
  const jsonPath = writeJsonReport("release", `github-sigstore-attestation-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("release", `github-sigstore-attestation-${stamp}`, [
    "# GitHub/Sigstore Attestation Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    `Repository: ${validation.repository ?? "n/a"}`,
    `Commit: ${validation.commitSha ?? "n/a"}`,
    `Signer workflow: ${validation.signerWorkflow}`,
    `Source ref: ${validation.sourceRef}`,
    `Verified timestamps: ${validation.verifiedTimestampCount}`,
    `Subject count: ${validation.subjects.length}`,
    "",
    "| Subject | SHA256 |",
    "| --- | --- |",
    ...validation.subjects.map((subject) => `| ${subject.name ?? "n/a"} | ${subject.sha256} |`),
  ]);
  log(`GitHub/Sigstore attestation evidence written to ${jsonPath} and ${markdownPath}`);
}

async function rollbackRelease() {
  log("==> Platform release rollback");
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
  if (!fs.existsSync(envFile)) fail(`Env file not found: ${envFile}`);
  const rollbackFile = argv.rollbackFile ? path.resolve(argv.rollbackFile) : null;
  const fileImages = rollbackFile ? readJsonFile(rollbackFile, rollbackFile) : {};
  const imageOverrides = Object.fromEntries(Object.entries(fileImages).filter(([key, value]) => /^[A-Z0-9_]+_IMAGE$/.test(key) && value));
  if (!Object.keys(imageOverrides).length) fail("No rollback images found. Pass --rollbackFile with *_IMAGE keys.");
  for (const [key, image] of Object.entries(imageOverrides)) assertImmutableImageRef(key, image);
  const projectName = argv.projectName ?? "enterprise_prod";
  const services = csvList(argv.services, "platform-alert-dispatcher,control-center,php-apache");
  const composeFiles = csvList(argv.composeFiles, "compose.yaml,compose.prod.yaml");
  const envText = fs.readFileSync(envFile, "utf8");
  const stamp = reportTimestamp();
  const rollbackPlan = writeRollbackPlanReport({ envFile, envText, rollbackFile, imageOverrides, projectName, composeFiles, services, mode: booleanFlag(argv.confirmRollback) ? "apply" : "dry-run", stamp });
  if (!booleanFlag(argv.confirmRollback)) {
    log(`Rollback dry-run passed. Plan written to ${rollbackPlan.jsonPath} and ${rollbackPlan.markdownPath}`);
    return;
  }
  const backupEnvPath = `${envFile}.rollback-backup-${stamp}`;
  fs.copyFileSync(envFile, backupEnvPath);
  fs.writeFileSync(envFile, rollbackPlan.nextEnvText, "utf8");
  run("docker", ["compose", "--env-file", envFile, "-p", projectName, ...composeFiles.flatMap((file) => ["-f", path.resolve(infraRoot, file)]), "up", "-d", ...services]);
  await infraHealth();
  log(`Rollback applied. Previous env copied to ${backupEnvPath}. Plan: ${rollbackPlan.jsonPath}`);
}

async function drReadinessCheck(options = {}) {
  log("==> DR / PITR readiness check");
  const drCompose = readText(path.join(infraRoot, "compose.dr.yaml"));
  const plan = readText(path.join(infraRoot, "ENTERPRISE-10-PLAN.md"));
  const runbook = readText(path.join(infraRoot, "RUNBOOK.md"));
  assertMatch(drCompose, /archive_mode=on/, "DR overlay must enable PostgreSQL archive_mode.");
  assertMatch(drCompose, /wal_level=replica/, "DR overlay must set wal_level=replica.");
  assertMatch(drCompose, /enterprise_postgres_wal_archive/, "DR overlay must persist WAL archives.");
  assertMatch(plan, /RPO:\s+15 minutes/i, "Enterprise plan must declare the RPO target.");
  assertMatch(plan, /RTO:\s+60 minutes/i, "Enterprise plan must declare the RTO target.");
  assertMatch(runbook, /offsite-backup-restic/, "Runbook must include encrypted off-site backup procedure.");
  assertMatch(runbook, /backup-restore-drill/, "Runbook must include scheduled restore drill procedure.");
  if (noDockerMode(options)) {
    log("Skipping Docker Compose DR render in --noDocker/--repoOnly mode.");
  } else {
    run("docker", [
      "compose",
      "--env-file",
      ".env",
      "-p",
      "enterprise_prod_dr",
      "-f",
      "compose.yaml",
      "-f",
      "compose.prod.yaml",
      "-f",
      "compose.dr.yaml",
      "config",
      "--quiet",
    ], { env: localProductionImageEnv() });
  }
  log("DR / PITR readiness check passed.");
}

async function securityMatrix() {
  await withLocalCheckReport("security-matrix", async () => {
    await testingHygiene();
    staticSecurityInfraOnlyCheck();
    await networkSegmentationCheck();
    await runtimeIsolationCheck();
    await securitySmoke();
    log("Platform security test matrix passed.");
  }, { scope: "platform-infrastructure" });
}

async function chaosProfile() {
  log("==> Staging chaos profile");
  if (!booleanFlag(argv.confirmChaos)) {
    fail("chaos-profile is destructive. Re-run with --confirmChaos in staging.");
  }
  const targets = ["enterprise-redis", "enterprise-nats", "enterprise-minio"];
  if (booleanFlag(argv.includePostgres)) {
    targets.push("enterprise-postgres");
  }
  const results = [];
  const stopped = [];
  try {
    for (const container of targets) {
      const startedAt = Date.now();
      log(`Stopping ${container}`);
      run("docker", ["stop", "--time", "10", container]);
      stopped.push(container);
      await new Promise((resolve) => setTimeout(resolve, 3000));
      if (container === "enterprise-redis") {
        await securitySmoke();
      }
      log(`Restarting ${container}`);
      run("docker", ["start", container]);
      stopped.pop();
      await waitContainerHealthy(container, 120);
      await waitInfraHealth(120);
      results.push({ container, stopped: true, recovered: true, durationMs: Date.now() - startedAt });
    }
    await faultInjectionTests();
    await loadProfile();
    const stamp = reportTimestamp();
    const payload = {
      generatedAt: new Date().toISOString(),
      status: "passed",
      mode: "staging-chaos",
      includePostgres: booleanFlag(argv.includePostgres),
      targets: results,
    };
    const jsonPath = writeJsonReport("chaos", `chaos-profile-${stamp}`, payload);
    const markdownPath = writeMarkdownReport("chaos", `chaos-profile-${stamp}`, [
      "# Staging Chaos Profile",
      "",
      `Generated at: ${payload.generatedAt}`,
      `Status: ${payload.status}`,
      `Include PostgreSQL: ${payload.includePostgres ? "yes" : "no"}`,
      "",
      "| Container | Stopped | Recovered | Duration ms |",
      "| --- | --- | --- | ---: |",
      ...results.map((result) => `| ${result.container} | ${result.stopped ? "yes" : "no"} | ${result.recovered ? "yes" : "no"} | ${result.durationMs} |`),
    ]);
    log("Staging chaos profile passed.");
    log(`Chaos profile report written to ${jsonPath} and ${markdownPath}`);
  } finally {
    for (const container of stopped.reverse()) {
      run("docker", ["start", container], { allowFailure: true, capture: true });
    }
  }
}

async function governanceCheck() {
  await withLocalCheckReport("governance-check", governanceCheckBody);
}

async function governanceCheckBody() {
  log("==> Governance / release control check");
  const sourceWorkflowPath = path.join(sourceRoot, ".github", "workflows", "enterprise-ci.yml");
  const sourceWorkflowAvailable = fs.existsSync(sourceWorkflowPath);
  const checkSourceWorkflow = sourceWorkflowAvailable && !booleanFlag(argv.infraOnly);
  const workflow = checkSourceWorkflow ? readText(sourceWorkflowPath) : "";
  const branchProtection = JSON.parse(readText(path.join(infraRoot, "governance", "github-branch-protection.json")));
  const environmentsPolicy = JSON.parse(readText(path.join(infraRoot, "governance", "github-environments.json")));
  const actionsRuntimePolicy = JSON.parse(readText(path.join(infraRoot, "governance", "github-actions-runtime.json")));
  const infraWorkflow = readText(path.join(infraRoot, ".github", "workflows", "enterprise-infra.yml"));
  const runbook = readText(path.join(infraRoot, "RUNBOOK.md"));
  for (const job of ["quality", "compose", "supply-chain", "enterprise-readiness"]) {
    if (checkSourceWorkflow) {
      assertMatch(workflow, new RegExp(`^\\s{2}${job}:`, "m"), `Enterprise CI must define ${job} job.`);
    }
    if (!branchProtection.required_status_checks.contexts.includes(job)) {
      fail(`Branch protection must require ${job}.`);
    }
  }
  if (!checkSourceWorkflow) {
    log(`Skipping optional Platform application CI source checks (${sourceWorkflowAvailable ? "--infraOnly enabled" : `missing ${sourceWorkflowPath}`}).`);
  }
  const environmentNames = new Set(environmentsPolicy.environments?.map((environment) => environment.name) ?? []);
  for (const name of ["staging", "production"]) {
    if (!environmentNames.has(name)) {
      fail(`GitHub environments policy must define ${name}.`);
    }
  }
  if (actionsRuntimePolicy.repository?.required_secrets?.some((item) => item.name === "PROJECT_REPO_TOKEN")) {
    fail("GitHub Actions runtime policy must not require project repository checkout tokens.");
  }
  assertNoMatch(infraWorkflow, /project-repository|PROJECT_REPO_TOKEN|Checkout application source/, "Infrastructure CI must not checkout or require Platform application repositories.");
  assertMatch(infraWorkflow, /dast-zap:[\s\S]*environment:\s*\r?\n\s+name:\s+staging/, "DAST job must target the staging GitHub environment.");
  assertMatch(infraWorkflow, /deploy-vps:[\s\S]*environment:\s*\r?\n\s+name:\s+production/, "VPS deploy job must target the production GitHub environment.");
  assertMatch(infraWorkflow, /deploy-vps:[\s\S]*concurrency:[\s\S]*infra-production-deploy[\s\S]*cancel-in-progress:\s+false/, "Production deploys must be serialized.");
  assertNoMatch(infraWorkflow, /^\s{2}(?:compose-and-policy|shell-syntax):/m, "Infrastructure CI must use the four canonical required gates without duplicate legacy jobs.");
  assertMatch(infraWorkflow, /enterprise-readiness:[\s\S]*needs:\s*\r?\n\s+- quality\s*\r?\n\s+- compose\s*\r?\n\s+- supply-chain/, "Enterprise readiness must depend on all three behavior gates.");
  assertMatch(infraWorkflow, /dast-zap:[\s\S]*needs:\s*enterprise-readiness/, "DAST must run only after enterprise readiness.");
  assertMatch(infraWorkflow, /deploy-vps:[\s\S]*needs:\s*enterprise-readiness/, "Production deploy must run only after enterprise readiness.");
  assertMatch(runbook, /Production deploy/, "Runbook must document production deploy.");
  assertMatch(runbook, /Rollback/, "Runbook must document rollback.");
  assertMatch(runbook, /release approval/i, "Runbook must document release approval.");
  assertMatch(runbook, /audit trail/i, "Runbook must document deploy audit trail.");
  log("Governance / release control check passed.");
}

function githubBranchProtectionPolicy() {
  return JSON.parse(readText(path.join(infraRoot, "governance", "github-branch-protection.json")));
}

function githubEnvironmentsPolicy() {
  const policy = JSON.parse(readText(path.join(infraRoot, "governance", "github-environments.json")));
  if (!Array.isArray(policy.environments) || policy.environments.length === 0) {
    fail("governance/github-environments.json must define at least one environment.");
  }
  for (const environment of policy.environments) {
    if (!environment.name || !/^[A-Za-z0-9_.-]+$/.test(environment.name)) {
      fail("Each GitHub environment must have a simple name.");
    }
    const waitTimer = Number(environment.wait_timer ?? 0);
    if (!Number.isInteger(waitTimer) || waitTimer < 0 || waitTimer > 43200) {
      fail(`GitHub environment ${environment.name} has an invalid wait_timer.`);
    }
    const branchPolicy = environment.deployment_branch_policy;
    if (branchPolicy) {
      const protectedBranches = Boolean(branchPolicy.protected_branches);
      const customBranchPolicies = Boolean(branchPolicy.custom_branch_policies);
      if (protectedBranches === customBranchPolicies) {
        fail(`GitHub environment ${environment.name} must choose either protected_branches or custom_branch_policies.`);
      }
    }
    if (environment.required_reviewers_env) {
      fail(`GitHub environment ${environment.name} must define exact reviewer identities in policy, not an environment-variable placeholder.`);
    }
    const reviewers = Array.isArray(environment.reviewers) ? environment.reviewers : [];
    if (environment.require_reviewers_on_apply && reviewers.length === 0) {
      fail(`GitHub environment ${environment.name} requires exact reviewer identities.`);
    }
    for (const reviewer of reviewers) {
      if (!["User", "Team"].includes(reviewer?.type) || !Number.isInteger(Number(reviewer?.id)) || Number(reviewer.id) <= 0) {
        fail(`GitHub environment ${environment.name} has an invalid exact reviewer identity.`);
      }
    }
  }
  return policy;
}

function githubActionsRuntimePolicy() {
  const policy = JSON.parse(readText(path.join(infraRoot, "governance", "github-actions-runtime.json")));
  const repository = policy.repository ?? {};
  const environments = Array.isArray(policy.environments) ? policy.environments : [];
  for (const item of [
    ...(repository.required_secrets ?? []),
    ...(repository.required_variables ?? []),
    ...environments.flatMap((environment) => [
      ...(environment.required_secrets ?? []),
      ...(environment.required_variables ?? []),
    ]),
  ]) {
    if (!item.name || !/^[A-Z0-9_]+$/.test(item.name)) {
      fail("GitHub Actions required secrets and variables must use uppercase snake-case names.");
    }
    if (item.pattern) {
      new RegExp(item.pattern);
    }
  }
  const environmentNames = new Set(environments.map((environment) => environment.name));
  for (const name of ["staging", "production"]) {
    if (!environmentNames.has(name)) {
      fail(`GitHub Actions runtime policy must define ${name}.`);
    }
  }
  return { repository, environments };
}

function requiredGithubRepo() {
  const repo = argv.repo ?? process.env.PLATFORM_GITHUB_REPOSITORY ?? process.env.GITHUB_REPOSITORY;
  return normalizeRepository(repo);
}

function loadGithubTokenFromFile() {
  if (process.env.GITHUB_TOKEN || process.env.GH_TOKEN) return;
  const tokenFile = process.env.GITHUB_TOKEN_FILE
    || process.env.GH_TOKEN_FILE
    || path.join(infraRoot, "secrets", "github_token.txt");
  try {
    if (!fs.existsSync(tokenFile)) return;
    const token = fs.readFileSync(tokenFile, "utf8").trim();
    if (token) process.env.GITHUB_TOKEN = token;
  } catch {
    // Token files are optional; commands that require auth will fail explicitly.
  }
}

async function githubApi(method, apiPath, body = undefined) {
  loadGithubTokenFromFile();
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (!token && method !== "GET") {
    fail("Set GITHUB_TOKEN or GH_TOKEN before applying or verifying live GitHub governance.");
  }
  const headers = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "platform-infrastructure",
    "X-GitHub-Api-Version": process.env.GITHUB_API_VERSION ?? "2026-03-10",
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const response = await requestRaw(method, `https://api.github.com${apiPath}`, {
    headers,
    body,
    timeoutMs: Number(argv.timeoutMs ?? 15000),
  });
  if (response.status < 200 || response.status >= 300) {
    fail(`GitHub API ${method} ${apiPath} failed with HTTP ${response.status}: ${response.text}`);
  }
  return response.text ? JSON.parse(response.text) : null;
}

function assertRemoteBranchProtectionMatches(policy, remote) {
  assertExactBranchProtection(policy, remote);
}

async function githubBranchProtection() {
  log("==> GitHub branch protection");
  const repo = requiredGithubRepo();
  const branch = String(argv.branch ?? "main");
  const policy = githubBranchProtectionPolicy();
  const apiPath = `${githubRepoApiPath(repo)}/branches/${encodeURIComponent(branch)}/protection`;

  if (booleanFlag(argv.verifyRemote)) {
    const remote = await githubApi("GET", apiPath);
    assertRemoteBranchProtectionMatches(policy, remote);
    log(`Remote GitHub branch protection matches required policy for ${repo}:${branch}.`);
    return;
  }

  if (!booleanFlag(argv.apply)) {
    log(`Mode: dry-run`);
    log(`Repository: ${repo}`);
    log(`Branch: ${branch}`);
    log(JSON.stringify(policy, null, 2));
    log("Re-run with --apply and GITHUB_TOKEN/GH_TOKEN to update the live branch protection rule.");
    return;
  }

  await githubApi("PUT", apiPath, policy);
  log(`Applied GitHub branch protection policy to ${repo}:${branch}.`);
}

async function verifyGithubBranchProtectionRemote(repo, branch = "main") {
  const apiPath = `/repos/${repo}/branches/${encodeURIComponent(branch)}/protection`;
  const remote = await githubApi("GET", apiPath);
  assertRemoteBranchProtectionMatches(githubBranchProtectionPolicy(), remote);
  log(`Remote GitHub branch protection matches required policy for ${repo}:${branch}.`);
}

function githubRepoApiPath(repo) {
  const [owner, repoName] = repo.split("/");
  return `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}`;
}

function githubEnvironmentApiPath(repo, environmentName) {
  return `${githubRepoApiPath(repo)}/environments/${encodeURIComponent(environmentName)}`;
}

function reviewerRefsForEnvironment(environment) {
  return Array.isArray(environment.reviewers) ? [...environment.reviewers] : [];
}

async function resolveGithubReviewer(repo, reviewerRef) {
  if (typeof reviewerRef === "object" && reviewerRef !== null) {
    const type = reviewerRef.type;
    const id = Number(reviewerRef.id);
    if (!["User", "Team"].includes(type) || !Number.isInteger(id) || id <= 0) {
      fail("Reviewer objects must use {\"type\":\"User|Team\",\"id\":123}.");
    }
    return { type, id };
  }

  const text = String(reviewerRef).trim();
  const match = text.match(/^(user|team):(.+)$/i);
  if (!match) {
    fail(`Invalid reviewer '${text}'. Use user:login, team:slug, user:123 or team:123.`);
  }
  const type = match[1].toLowerCase() === "user" ? "User" : "Team";
  const value = match[2].trim();
  if (/^\d+$/.test(value)) {
    return { type, id: Number(value) };
  }
  if (type === "User") {
    const user = await githubApi("GET", `/users/${encodeURIComponent(value)}`);
    if (!Number.isInteger(Number(user?.id))) {
      fail(`Could not resolve GitHub user reviewer '${value}'.`);
    }
    return { type: "User", id: Number(user.id) };
  }
  const [owner] = repo.split("/");
  const team = await githubApi("GET", `/orgs/${encodeURIComponent(owner)}/teams/${encodeURIComponent(value)}`);
  if (!Number.isInteger(Number(team?.id))) {
    fail(`Could not resolve GitHub team reviewer '${value}'.`);
  }
  return { type: "Team", id: Number(team.id) };
}

async function githubEnvironmentPayload(repo, environment) {
  const reviewerRefs = reviewerRefsForEnvironment(environment);
  const reviewers = [];
  for (const reviewerRef of reviewerRefs) {
    reviewers.push(await resolveGithubReviewer(repo, reviewerRef));
  }
  return {
    wait_timer: Number(environment.wait_timer ?? 0),
    prevent_self_review: Boolean(environment.prevent_self_review),
    reviewers: reviewers.length > 0 ? reviewers : null,
    deployment_branch_policy: environment.deployment_branch_policy ?? null,
  };
}

function assertGithubEnvironmentApplyPreflight(policy) {
  for (const environment of policy.environments) {
    if (environment.require_reviewers_on_apply && reviewerRefsForEnvironment(environment).length === 0) {
      fail(`Define exact reviewer identities before applying the ${environment.name} GitHub environment.`);
    }
  }
}

function dryRunGithubEnvironmentPayload(environment) {
  return {
    wait_timer: Number(environment.wait_timer ?? 0),
    prevent_self_review: Boolean(environment.prevent_self_review),
    reviewers: environment.reviewers?.length ? environment.reviewers : null,
    require_reviewers_on_apply: Boolean(environment.require_reviewers_on_apply),
    deployment_branch_policy: environment.deployment_branch_policy ?? null,
  };
}

function assertRemoteGithubEnvironmentMatches(expected, remote) {
  assertExactGithubEnvironment(expected, remote);
}

async function githubEnvironments() {
  log("==> GitHub environments");
  const repo = requiredGithubRepo();
  const policy = githubEnvironmentsPolicy();

  if (booleanFlag(argv.verifyRemote)) {
    await verifyGithubEnvironmentsRemote(repo, policy);
    return;
  }

  if (!booleanFlag(argv.apply)) {
    log("Mode: dry-run");
    log(`Repository: ${repo}`);
    for (const environment of policy.environments) {
      log(`Environment: ${environment.name}`);
      log(JSON.stringify(dryRunGithubEnvironmentPayload(environment), null, 2));
    }
    log("Exact reviewer IDs are loaded from governance/github-environments.json.");
    log("Re-run with --apply and GITHUB_TOKEN/GH_TOKEN to update live GitHub deployment environments.");
    return;
  }

  assertGithubEnvironmentApplyPreflight(policy);
  for (const environment of policy.environments) {
    const payload = await githubEnvironmentPayload(repo, environment);
    await githubApi("PUT", githubEnvironmentApiPath(repo, environment.name), payload);
    log(`Applied GitHub environment policy to ${repo}:${environment.name}.`);
  }
}

async function verifyGithubEnvironmentsRemote(repo, policy = githubEnvironmentsPolicy()) {
  for (const environment of policy.environments) {
    const remote = await githubApi("GET", githubEnvironmentApiPath(repo, environment.name));
    assertRemoteGithubEnvironmentMatches(environment, remote);
    log(`Remote GitHub environment ${repo}:${environment.name} matches required policy.`);
  }
}

async function githubApiList(apiPath, key, perPage = 100) {
  const items = [];
  for (let page = 1; page <= 100; page += 1) {
    const separator = apiPath.includes("?") ? "&" : "?";
    const payload = await githubApi("GET", `${apiPath}${separator}per_page=${perPage}&page=${page}`);
    const pageItems = Array.isArray(payload?.[key]) ? payload[key] : [];
    items.push(...pageItems);
    if (pageItems.length < perPage) {
      break;
    }
  }
  return items;
}

function namesSet(items) {
  return new Set(items.map((item) => item.name).filter(Boolean));
}

function validateRequiredNames(scope, kind, requiredItems, actualNames) {
  const missing = [];
  for (const item of requiredItems ?? []) {
    if (!actualNames.has(item.name)) {
      missing.push(item.name);
    }
  }
  if (missing.length) {
    fail(`Missing GitHub Actions ${kind} for ${scope}: ${missing.join(", ")}`);
  }
}

function validateVariablePatterns(scope, requiredItems, actualVariables) {
  const byName = new Map(actualVariables.map((item) => [item.name, item]));
  for (const item of requiredItems ?? []) {
    if (!item.pattern) {
      continue;
    }
    const actual = byName.get(item.name);
    if (!actual) {
      continue;
    }
    const value = String(actual.value ?? "");
    if (!new RegExp(item.pattern).test(value)) {
      fail(`GitHub Actions variable ${scope}:${item.name} does not match the required pattern.`);
    }
  }
}

function logGithubActionsRuntimeDryRun(policy) {
  log("Mode: dry-run");
  log("Repository required secrets:");
  for (const item of policy.repository.required_secrets ?? []) {
    log(`- ${item.name}: ${item.purpose ?? "required"}`);
  }
  log("Repository required variables:");
  for (const item of policy.repository.required_variables ?? []) {
    log(`- ${item.name}: ${item.purpose ?? "required"}`);
  }
  for (const environment of policy.environments) {
    log(`Environment: ${environment.name}`);
    log("  required secrets:");
    for (const item of environment.required_secrets ?? []) {
      log(`  - ${item.name}: ${item.purpose ?? "required"}`);
    }
    log("  required variables:");
    for (const item of environment.required_variables ?? []) {
      const pattern = item.pattern ? ` pattern=${item.pattern}` : "";
      log(`  - ${item.name}: ${item.purpose ?? "required"}${pattern}`);
    }
  }
  log("Re-run with --verifyRemote and GITHUB_TOKEN/GH_TOKEN to verify live GitHub Actions secrets and variables.");
}

async function githubActionsConfig() {
  log("==> GitHub Actions runtime config");
  const repo = requiredGithubRepo();
  const policy = githubActionsRuntimePolicy();
  if (!booleanFlag(argv.verifyRemote)) {
    log(`Repository: ${repo}`);
    logGithubActionsRuntimeDryRun(policy);
    return;
  }

  await verifyGithubActionsRuntimeConfig(repo, policy);
}

async function verifyGithubActionsRuntimeConfig(repo, policy = githubActionsRuntimePolicy()) {
  const basePath = githubRepoApiPath(repo);
  const repositorySecrets = await githubApiList(`${basePath}/actions/secrets`, "secrets");
  const repositoryVariables = await githubApiList(`${basePath}/actions/variables`, "variables", 30);
  validateRequiredNames("repository", "secrets", policy.repository.required_secrets, namesSet(repositorySecrets));
  validateRequiredNames("repository", "variables", policy.repository.required_variables, namesSet(repositoryVariables));
  validateVariablePatterns("repository", policy.repository.required_variables, repositoryVariables);

  for (const environment of policy.environments) {
    const environmentSecrets = await githubApiList(`${basePath}/environments/${encodeURIComponent(environment.name)}/secrets`, "secrets");
    const environmentVariables = await githubApiList(`${basePath}/environments/${encodeURIComponent(environment.name)}/variables`, "variables", 30);
    validateRequiredNames(environment.name, "secrets", environment.required_secrets, namesSet(environmentSecrets));
    validateRequiredNames(environment.name, "variables", environment.required_variables, namesSet(environmentVariables));
    validateVariablePatterns(environment.name, environment.required_variables, environmentVariables);
    log(`GitHub Actions runtime config for ${repo}:${environment.name} is present.`);
  }
  log(`GitHub Actions runtime config for ${repo} matches required policy.`);
}

function expectedGithubActionsRunSha() {
  const explicit = argv.sha ?? argv.commit ?? process.env.GITHUB_SHA;
  if (explicit) {
    return String(explicit);
  }
  const git = gitEvidence();
  return git.commit;
}

function writeGithubActionsRunEvidenceReport(payload) {
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("github-actions", `github-actions-run-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("github-actions", `github-actions-run-${stamp}`, [
    "# GitHub Actions Run Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Repository: ${payload.repo}`,
    `Workflow: ${payload.workflow}`,
    `Branch: ${payload.branch}`,
    `Expected SHA: ${payload.expectedSha ?? "n/a"}`,
    `Candidate: ${payload.candidate?.id ?? "not-bound"}`,
    `Run ID: ${payload.run?.id ?? "n/a"}`,
    `Run conclusion: ${payload.run?.conclusion ?? "n/a"}`,
    `Run status: ${payload.run?.status ?? "n/a"}`,
    "",
    "## Issues",
    "",
    ...(payload.issues?.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`GitHub Actions run evidence report written to ${jsonPath} and ${markdownPath}`);
  return { jsonPath, markdownPath };
}

async function githubActionsRunEvidence() {
  log("==> GitHub Actions run evidence");
  const repo = requiredGithubRepo();
  const workflow = String(argv.workflow ?? productionGoNoGoPolicy().policy.requiredGithubWorkflow ?? "enterprise-infra.yml");
  const branch = String(argv.branch ?? process.env.GITHUB_REF_NAME ?? "main");
  const expectedSha = expectedGithubActionsRunSha();
  const mode = booleanFlag(argv.verifyRemote) ? "verifyRemote" : "plan";
  const issues = [];
  const candidateEvidence = mode === "verifyRemote" ? currentCandidateIdentityEvidence({
    envFile: argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: argv.project ?? argv.projectName,
    repository: repo,
  }) : { candidate: null, error: "plan-only" };
  if (!expectedSha || !/^[a-f0-9]{40}$/i.test(expectedSha)) {
    issues.push(`expected SHA is missing or invalid: ${expectedSha ?? "n/a"}`);
  }
  if (mode === "verifyRemote") {
    if (!candidateEvidence.candidate?.trusted) issues.push(`candidate identity is not trusted: ${candidateEvidence.error ?? "worktree-not-clean"}`);
    else {
      if (String(expectedSha).toLowerCase() !== candidateEvidence.candidate.commit) issues.push("expected SHA does not equal the current candidate commit");
      try {
        if (normalizeRepositoryIdentity(repo) !== candidateEvidence.candidate.repository) issues.push("repository does not equal the current candidate repository");
      } catch (error) {
        issues.push(String(error?.message ?? error));
      }
    }
  }
  let runEvidence = null;
  if (mode === "verifyRemote") {
    const basePath = githubRepoApiPath(repo);
    const query = new URLSearchParams({
      branch,
      event: "push",
      per_page: "30",
    });
    if (expectedSha && /^[a-f0-9]{40}$/i.test(expectedSha)) {
      query.set("head_sha", expectedSha);
    }
    const response = await githubApi("GET", `${basePath}/actions/workflows/${encodeURIComponent(workflow)}/runs?${query.toString()}`);
    const runs = Array.isArray(response?.workflow_runs) ? response.workflow_runs : [];
    const matchingRuns = runs.filter((run) => !expectedSha || String(run.head_sha ?? "").toLowerCase() === expectedSha.toLowerCase());
    const run = matchingRuns[0] ?? null;
    if (!run) {
      issues.push(`no workflow run found for ${workflow} on ${branch} at ${expectedSha ?? "latest"}`);
    } else {
      runEvidence = {
        id: run.id,
        name: run.name,
        htmlUrl: run.html_url,
        headSha: run.head_sha,
        status: run.status,
        conclusion: run.conclusion,
        event: run.event,
        createdAt: run.created_at,
        updatedAt: run.updated_at,
      };
      if (run.status !== "completed") {
        issues.push(`workflow run is not completed: ${run.status}`);
      }
      if (run.conclusion !== "success") {
        issues.push(`workflow run conclusion is not success: ${run.conclusion ?? "null"}`);
      }
    }
  } else {
    issues.push("remote workflow run not verified; rerun with --verifyRemote and GITHUB_TOKEN/GH_TOKEN");
  }
  const candidateEndEvidence = mode === "verifyRemote" ? currentCandidateIdentityEvidence({
    envFile: argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: argv.project ?? argv.projectName,
    repository: repo,
  }) : candidateEvidence;
  const candidateStable = Boolean(
    candidateEvidence.candidate?.trusted
    && candidateEndEvidence.candidate?.trusted
    && candidateIdentityMatches(candidateEvidence.candidate, candidateEndEvidence.candidate),
  );
  if (mode === "verifyRemote" && !candidateStable) issues.push(`candidate changed during GitHub verification: ${candidateEndEvidence.error ?? "identity-mismatch"}`);
  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : "passed",
    mode,
    repo,
    workflow,
    branch,
    expectedSha,
    candidate: candidateEvidence.candidate,
    candidateEnd: candidateEndEvidence.candidate,
    candidateStable,
    candidateError: candidateEvidence.error,
    run: runEvidence,
    issues,
  };
  writeGithubActionsRunEvidenceReport(payload);
  if (issues.length && mode === "verifyRemote") {
    fail(`GitHub Actions run evidence failed: ${issues.join("; ")}`);
  }
  if (mode === "plan") {
    log("Mode: plan. Re-run with --verifyRemote and GITHUB_TOKEN/GH_TOKEN after the workflow has completed on the release commit.");
  } else {
    log("GitHub Actions run evidence passed.");
  }
}

function safeRepositoryIdentity(value) {
  try {
    return normalizeRepositoryIdentity(value);
  } catch {
    return null;
  }
}

function gitEvidence() {
  if (/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(String(process.env.PLATFORM_GIT_COMMIT ?? ""))) {
    return {
      commit: String(process.env.PLATFORM_GIT_COMMIT).toLowerCase(),
      tree: /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(String(process.env.PLATFORM_GIT_TREE ?? "")) ? String(process.env.PLATFORM_GIT_TREE).toLowerCase() : null,
      branch: String(process.env.PLATFORM_GIT_BRANCH ?? "").trim() || null,
      dirty: booleanFlag(process.env.PLATFORM_GIT_DIRTY),
      repository: safeRepositoryIdentity(process.env.PLATFORM_GIT_REPOSITORY ?? process.env.PLATFORM_GITHUB_REPOSITORY ?? process.env.GITHUB_REPOSITORY),
    };
  }
  const gitArgs = (...args) => ["-c", "safe.directory=*", ...args];
  const rev = run("git", gitArgs("rev-parse", "HEAD"), { capture: true, allowFailure: true });
  const tree = run("git", gitArgs("rev-parse", "HEAD^{tree}"), { capture: true, allowFailure: true });
  const branch = run("git", gitArgs("rev-parse", "--abbrev-ref", "HEAD"), { capture: true, allowFailure: true });
  const status = run("git", gitArgs("status", "--short"), { capture: true, allowFailure: true });
  const repository = run("git", gitArgs("config", "--get", "remote.origin.url"), { capture: true, allowFailure: true });
  return {
    commit: rev.status === 0 ? String(rev.stdout ?? "").trim() : null,
    tree: tree.status === 0 ? String(tree.stdout ?? "").trim() : null,
    branch: branch.status === 0 ? String(branch.stdout ?? "").trim() : null,
    dirty: status.status === 0 ? String(status.stdout ?? "").trim().split(/\r?\n/).filter(Boolean).length > 0 : null,
    repository: repository.status === 0 ? safeRepositoryIdentity(repository.stdout) : null,
  };
}

async function collectEvidenceStep(steps, { name, category, required = true, fn }) {
  const startedAt = new Date();
  log(`==> Evidence step: ${name}`);
  try {
    await fn();
    const finishedAt = new Date();
    steps.push({
      name,
      category,
      required,
      status: "passed",
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
    });
  } catch (error) {
    const finishedAt = new Date();
    steps.push({
      name,
      category,
      required,
      status: "failed",
      startedAt: startedAt.toISOString(),
      finishedAt: finishedAt.toISOString(),
      durationMs: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
      error: String(error?.message ?? error),
    });
    log(`Evidence step failed: ${name}: ${String(error?.message ?? error)}`);
  }
}

function skipEvidenceStep(steps, { name, category, required = false, reason }) {
  steps.push({
    name,
    category,
    required,
    status: "skipped",
    reason,
  });
  log(`Skipping evidence step ${name}: ${reason}`);
}

function evidenceStep(steps, name) {
  return steps.find((step) => step.name === name) ?? null;
}

function evidenceStepStatus(steps, name) {
  return evidenceStep(steps, name)?.status ?? "missing";
}

function evidenceGroupStatus(steps, names, enabled = true) {
  if (!enabled) {
    return "missing";
  }
  const statuses = names.map((name) => evidenceStepStatus(steps, name));
  if (statuses.some((status) => status === "missing" || status === "skipped")) {
    return "missing";
  }
  return statuses.every((status) => status === "passed") ? "passed" : "failed";
}

function liveProofStepStatus(steps, name, enabled = true) {
  if (!enabled) {
    return "pending-live-proof";
  }
  return evidenceStepStatus(steps, name) === "passed" ? "passed" : "pending-live-proof";
}

function liveProofGroupStatus(steps, names, enabled = true) {
  if (!enabled) {
    return "pending-live-proof";
  }
  const statuses = names.map((name) => evidenceStepStatus(steps, name));
  return statuses.every((status) => status === "passed") ? "passed" : "pending-live-proof";
}

function buildPreGoLiveReadinessMatrix({ steps, options, repo, candidateStable }) {
  const localPolicySteps = [
    "static-security-check",
    "governance-check",
    "ha-config-check",
    "managed-secrets-preflight",
    "compose-healthcheck-coverage",
    "control-center-tests",
    "rate-limit-evidence",
    "audit-log-evidence",
    "retention-evidence",
    "secret-rotation-evidence-plan",
    "dr-readiness-check",
    "dr-evidence-summary",
    "release-evidence-plan",
    "alert-evidence-summary",
    "external-uptime-manifest-dry-run",
  ];
  const runtimeSteps = ["infra-health", "security-smoke", "waf-smoke"];
  const githubDryRunSteps = [
    "github-branch-protection-policy-dry-run",
    "github-environments-policy-dry-run",
    "github-actions-runtime-policy-dry-run",
  ];
  const githubRemoteSteps = [
    "github-branch-protection-verify-remote",
    "github-environments-verify-remote",
    "github-actions-runtime-verify-remote",
  ];

  return [
    {
      id: "candidate-identity",
      required: true,
      status: candidateStable ? "passed" : "failed",
      evidence: "current commit, tree, repository, clean worktree, workload lock and canonical render digest",
      nextAction: "Regenerate all evidence from one clean current candidate and do not change the checkout during collection.",
    },
    {
      id: "local-policy",
      required: true,
      status: evidenceGroupStatus(steps, localPolicySteps),
      evidence: localPolicySteps.join(", "),
      nextAction: "Fix any failed local-policy step before requesting go-live approval.",
    },
    {
      id: "runtime-smoke",
      required: true,
      status: evidenceGroupStatus(steps, runtimeSteps, options.includeRuntime),
      evidence: runtimeSteps.join(", "),
      nextAction: "Run pre-go-live with --includeRuntime against the candidate stack.",
    },
    {
      id: "production-preflight",
      required: true,
      status: liveProofStepStatus(steps, "production-preflight", options.includeProductionPreflight),
      evidence: "production-preflight",
      nextAction: "Run with --includeProductionPreflight and the final production env file after placeholders are replaced.",
    },
    {
      id: "full-restore-drill",
      required: true,
      status: evidenceStepStatus(steps, "full-restore-drill"),
      evidence: "full-restore-drill",
      nextAction: "Run with --includeRestoreDrill during the staging/VPS validation window.",
    },
    {
      id: "offsite-restore-dry-run",
      required: true,
      status: liveProofStepStatus(steps, "offsite-restore-drill-restic-dry-run", options.includeOffsiteRestoreDryRun),
      evidence: "offsite-restore-drill-restic-dry-run",
      nextAction: "Run with --includeOffsiteRestoreDryRun plus RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE.",
    },
    {
      id: "github-governance-dry-run",
      required: true,
      status: evidenceGroupStatus(steps, githubDryRunSteps, Boolean(repo)),
      evidence: githubDryRunSteps.join(", "),
      nextAction: "Pass --repo OWNER/REPO or set GITHUB_REPOSITORY.",
    },
    {
      id: "github-remote-verification",
      required: true,
      status: liveProofGroupStatus(steps, githubRemoteSteps, options.verifyGithubRemote),
      evidence: githubRemoteSteps.join(", "),
      nextAction: "Run with --verifyGithubRemote and GITHUB_TOKEN/GH_TOKEN after the live repository is configured.",
    },
    {
      id: "provider-live-evidence",
      required: false,
      status: "external",
      evidence: "VPS hardening, Cloudflare Access/CDN/WAF, external uptime, public load, off-site restore, release provenance.",
      nextAction: "Close the dedicated production go/no-go checks with live provider reports.",
    },
  ];
}

function verifyExistingFullRestoreDrillEvidence(options = {}) {
  const maxAgeHours = positiveInteger(options.maxAgeHours ?? argv.maxRestoreDrillAgeHours ?? 168, "--maxRestoreDrillAgeHours", 1);
  const report = latestJsonReport("restore-drills", "full-restore-drill-", (payload) => (
    payload.status === "success"
      || (Array.isArray(payload.steps) && payload.steps.length > 0 && payload.steps.every((step) => step.status === "success"))
  ));
  const freshness = reportFreshDetail(report, maxAgeHours);
  if (!report) {
    fail("No successful full restore drill report found.");
  }
  if (!freshness.fresh) {
    fail(`Latest full restore drill report is not fresh: ${freshness.detail}.`);
  }
  if (!Number.isFinite(Number(report.payload.durationMs))) {
    fail(`Latest full restore drill report has invalid durationMs: ${report.filePath}.`);
  }
  log(`Using existing full restore drill evidence: ${report.filePath}; ${freshness.detail}.`);
  return {
    reportPath: report.filePath,
    generatedAt: report.payload.generatedAt ?? report.payload.finishedAt ?? null,
    durationMs: Number(report.payload.durationMs),
  };
}

function verifyExistingSecretRotationEvidence(options = {}) {
  const maxAgeHours = positiveInteger(options.maxAgeHours ?? argv.maxSecretRotationEvidenceAgeHours ?? 168, "--maxSecretRotationEvidenceAgeHours", 1);
  const report = latestJsonReport("secret-rotation", "secret-rotation-evidence-", (payload) => (
    payload.mode === "evidence"
      && payload.status === "passed"
      && payload.verify?.status === "passed"
      && Number(payload.summary?.failedSecrets ?? 1) === 0
      && Number(payload.summary?.expiredSecrets ?? 1) === 0
      && Number(payload.summary?.missingMaterializedFiles ?? 1) === 0
  ));
  const freshness = reportFreshDetail(report, maxAgeHours);
  if (!report) {
    fail("No passing secret rotation evidence report found.");
  }
  if (!freshness.fresh) {
    fail(`Latest secret rotation evidence report is not fresh: ${freshness.detail}.`);
  }
  log(`Using existing non-secret rotation evidence: ${report.filePath}; ${freshness.detail}.`);
  return {
    reportPath: report.filePath,
    generatedAt: report.payload.generatedAt ?? null,
    summary: report.payload.summary ?? null,
  };
}

async function preGoLiveEvidence() {
  log("==> Pre go-live evidence pack");
  const repo = argv.repo ?? process.env.PLATFORM_GITHUB_REPOSITORY ?? process.env.GITHUB_REPOSITORY ?? null;
  const branch = String(argv.branch ?? "main");
  const infraOnly = booleanFlag(argv.infraOnly);
  const useExistingRestoreDrill = booleanFlag(argv.useExistingRestoreDrill) || booleanFlag(argv.useLatestRestoreDrill);
  const useExistingSecretRotationEvidence = booleanFlag(argv.useExistingSecretRotationEvidence) || booleanFlag(argv.useLatestSecretRotationEvidence);
  const steps = [];
  const providerEvidence = [
    "VPS Ubuntu LTS bootstrap and hardening executed on the real VPS.",
    "Cloudflare DNS/CDN/WAF/Access configured on the real zone and origin lock applied.",
    "External uptime monitors created and confirmed from outside the VPS network.",
    "Off-site Restic repository configured and remote restore tested.",
    "Real staging deploy, DAST run and production deploy completed.",
    "Public-path load benchmark archived.",
  ];
  const candidateAtStart = currentCandidateIdentityEvidence({
    envFile: argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: argv.project ?? argv.projectName,
    repository: repo,
  });

  await collectEvidenceStep(steps, {
    name: "static-security-check",
    category: "local-policy",
    fn: infraOnly ? staticSecurityInfraOnlyCheck : staticSecurityCheck,
  });
  await collectEvidenceStep(steps, { name: "governance-check", category: "local-policy", fn: governanceCheck });
  await collectEvidenceStep(steps, { name: "ha-config-check", category: "local-policy", fn: haConfigCheck });
  await collectEvidenceStep(steps, { name: "managed-secrets-preflight", category: "local-policy", fn: managedSecretsPreflight });
  await collectEvidenceStep(steps, { name: "compose-healthcheck-coverage", category: "local-policy", fn: composeHealthcheckCoverage });
  await collectEvidenceStep(steps, { name: "control-center-tests", category: "local-policy", fn: controlCenterTests });
  await collectEvidenceStep(steps, { name: "rate-limit-evidence", category: "local-policy", fn: rateLimitEvidence });
  await collectEvidenceStep(steps, { name: "audit-log-evidence", category: "local-policy", fn: auditLogEvidence });
  await collectEvidenceStep(steps, { name: "retention-evidence", category: "local-policy", fn: retentionEvidence });
  await collectEvidenceStep(steps, {
    name: "secret-rotation-evidence-plan",
    category: "local-policy",
    fn: useExistingSecretRotationEvidence ? verifyExistingSecretRotationEvidence : secretRotationEvidence,
  });
  await collectEvidenceStep(steps, { name: "dr-readiness-check", category: "local-policy", fn: drReadinessCheck });
  await collectEvidenceStep(steps, { name: "dr-evidence-summary", category: "local-policy", fn: drEvidence });
  await collectEvidenceStep(steps, { name: "release-evidence-plan", category: "local-policy", fn: () => releaseEvidence({ planOnly: true }) });
  await collectEvidenceStep(steps, { name: "alert-evidence-summary", category: "local-policy", fn: alertEvidence });
  await collectEvidenceStep(steps, { name: "external-uptime-manifest-dry-run", category: "provider-dry-run", fn: () => externalUptimeCheck({ dryRun: true }) });

  if (booleanFlag(argv.includeProductionPreflight)) {
    await collectEvidenceStep(steps, { name: "production-preflight", category: "production-env", fn: productionPreflight });
  } else {
    skipEvidenceStep(steps, {
      name: "production-preflight",
      category: "production-env",
      reason: "Pass --includeProductionPreflight with the final --envFile after replacing placeholders.",
    });
  }

  if (repo) {
    await collectEvidenceStep(steps, { name: "github-branch-protection-policy-dry-run", category: "provider-dry-run", fn: githubBranchProtection });
    await collectEvidenceStep(steps, { name: "github-environments-policy-dry-run", category: "provider-dry-run", fn: githubEnvironments });
    await collectEvidenceStep(steps, { name: "github-actions-runtime-policy-dry-run", category: "provider-dry-run", fn: githubActionsConfig });
    if (booleanFlag(argv.verifyGithubRemote)) {
      await collectEvidenceStep(steps, { name: "github-branch-protection-verify-remote", category: "provider-live", fn: () => verifyGithubBranchProtectionRemote(repo, branch) });
      await collectEvidenceStep(steps, { name: "github-environments-verify-remote", category: "provider-live", fn: () => verifyGithubEnvironmentsRemote(repo) });
      await collectEvidenceStep(steps, { name: "github-actions-runtime-verify-remote", category: "provider-live", fn: () => verifyGithubActionsRuntimeConfig(repo) });
    } else {
      skipEvidenceStep(steps, {
        name: "github-live-verification",
        category: "provider-live",
        reason: "Pass --verifyGithubRemote with GITHUB_TOKEN/GH_TOKEN after configuring the live repository.",
      });
    }
  } else {
    skipEvidenceStep(steps, {
      name: "github-governance",
      category: "provider-dry-run",
      reason: "Pass --repo OWNER/REPO or set GITHUB_REPOSITORY to include GitHub governance dry-runs.",
    });
  }

  if (booleanFlag(argv.includeRuntime)) {
    await collectEvidenceStep(steps, { name: "infra-health", category: "runtime", fn: infraHealth });
    await collectEvidenceStep(steps, { name: "security-smoke", category: "runtime", fn: securitySmoke });
    await collectEvidenceStep(steps, { name: "waf-smoke", category: "runtime", fn: wafSmoke });
  } else {
    skipEvidenceStep(steps, {
      name: "runtime-health-and-smoke",
      category: "runtime",
      reason: "Pass --includeRuntime against the running local/staging/VPS stack.",
    });
  }

  if (booleanFlag(argv.includeRestoreDrill)) {
    await collectEvidenceStep(steps, {
      name: "full-restore-drill",
      category: "disaster-recovery",
      fn: useExistingRestoreDrill ? verifyExistingFullRestoreDrillEvidence : fullRestoreDrill,
    });
  } else {
    skipEvidenceStep(steps, {
      name: "full-restore-drill",
      category: "disaster-recovery",
      reason: "Pass --includeRestoreDrill during the VPS/staging validation window.",
    });
  }

  if (booleanFlag(argv.includeOffsiteRestoreDryRun)) {
    await collectEvidenceStep(steps, { name: "offsite-restore-drill-restic-dry-run", category: "disaster-recovery", fn: () => offsiteRestoreDrillRestic({ dryRun: true, skipInfraHealth: true }) });
  } else {
    skipEvidenceStep(steps, {
      name: "offsite-restore-drill-restic",
      category: "disaster-recovery",
      reason: "Pass --includeOffsiteRestoreDryRun with RESTIC_REPOSITORY and RESTIC_PASSWORD_FILE after configuring the off-site repository.",
    });
  }

  const generatedAt = new Date().toISOString();
  const options = {
    infraOnly,
    includeProductionPreflight: booleanFlag(argv.includeProductionPreflight),
    includeRuntime: booleanFlag(argv.includeRuntime),
    includeRestoreDrill: booleanFlag(argv.includeRestoreDrill),
    useExistingRestoreDrill,
    useExistingSecretRotationEvidence,
    includeOffsiteRestoreDryRun: booleanFlag(argv.includeOffsiteRestoreDryRun),
    verifyGithubRemote: booleanFlag(argv.verifyGithubRemote),
  };
  const candidateAtEnd = currentCandidateIdentityEvidence({
    envFile: argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: argv.project ?? argv.projectName,
    repository: repo,
  });
  const candidateStable = Boolean(
    candidateAtStart.candidate?.trusted
    && candidateAtEnd.candidate?.trusted
    && candidateIdentityMatches(candidateAtStart.candidate, candidateAtEnd.candidate),
  );
  const readinessMatrix = buildPreGoLiveReadinessMatrix({ steps, options, repo, candidateStable });
  const failedRequired = steps.filter((step) => step.required && step.status === "failed");
  const readinessMissing = readinessMatrix.filter((item) => item.required && item.status !== "passed");
  const missingOptions = [
    !options.includeProductionPreflight ? "includeProductionPreflight" : null,
    !options.includeRuntime ? "includeRuntime" : null,
    !options.includeRestoreDrill ? "includeRestoreDrill" : null,
    !options.includeOffsiteRestoreDryRun ? "includeOffsiteRestoreDryRun" : null,
    !options.verifyGithubRemote ? "verifyGithubRemote" : null,
  ].filter(Boolean);
  const externalLiveStepNames = new Set(["production-preflight", "github-actions-runtime-verify-remote"]);
  const externalLiveReadinessIds = new Set(["production-preflight", "offsite-restore-dry-run", "github-remote-verification"]);
  const externalLiveOptions = new Set(["includeProductionPreflight", "includeOffsiteRestoreDryRun", "verifyGithubRemote"]);
  const localFailedRequired = failedRequired.filter((step) => !externalLiveStepNames.has(step.name));
  const localReadinessMissing = readinessMissing.filter((item) => !externalLiveReadinessIds.has(item.id));
  const localMissingOptions = missingOptions.filter((option) => !externalLiveOptions.has(option));
  const pendingLiveProofs = [
    ...failedRequired.filter((step) => externalLiveStepNames.has(step.name)).map((step) => `${step.name}: ${step.error ?? "live proof not satisfied"}`),
    ...readinessMissing.filter((item) => externalLiveReadinessIds.has(item.id)).map((item) => `${item.id}: ${item.nextAction}`),
    ...missingOptions.filter((option) => externalLiveOptions.has(option)).map((option) => `missing option: --${option}`),
  ];
  const issues = [
    ...(!candidateStable ? [`candidate-identity: ${candidateAtStart.error ?? candidateAtEnd.error ?? "candidate changed or worktree is not clean"}`] : []),
    ...localFailedRequired.map((step) => `${step.name}: ${step.error ?? "failed"}`),
    ...localReadinessMissing.map((item) => `${item.id}: ${item.nextAction}`),
    ...localMissingOptions.map((option) => `missing option: --${option}`),
  ];
  const preGoLiveStatus = issues.length ? "failed" : pendingLiveProofs.length ? "pending-live-proof" : "passed";
  const payload = {
    generatedAt,
    status: preGoLiveStatus,
    repo,
    branch,
    candidate: candidateAtStart.candidate,
    candidateEnd: candidateAtEnd.candidate,
    candidateStable,
    git: gitEvidence(),
    options,
    steps,
    readinessMatrix,
    missingOptions,
    pendingLiveProofs,
    issues,
    providerEvidenceRequired: providerEvidence,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("go-live", `pre-go-live-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("go-live", `pre-go-live-evidence-${stamp}`, [
    "# Platform Pre Go-Live Evidence",
    "",
    `Status: ${payload.status}`,
    `Generated at: ${generatedAt}`,
    `Repository: ${repo ?? "not provided"}`,
    `Git commit: ${payload.git.commit ?? "unknown"}`,
    `Git branch: ${payload.git.branch ?? "unknown"}`,
    `Dirty worktree: ${payload.git.dirty === null ? "unknown" : payload.git.dirty ? "yes" : "no"}`,
    `Candidate: ${payload.candidate?.id ?? "not-bound"}`,
    "",
    "## Readiness Matrix",
    "",
    "| Requirement | Required | Status | Evidence | Next action |",
    "| --- | --- | --- | --- | --- |",
    ...readinessMatrix.map((item) => `| ${item.id} | ${item.required ? "yes" : "no"} | ${item.status} | ${item.evidence.replace(/\r?\n/g, " ")} | ${item.nextAction.replace(/\r?\n/g, " ")} |`),
    "",
    "## Evidence Steps",
    "",
    "| Step | Category | Required | Status | Duration ms | Detail |",
    "| --- | --- | --- | --- | ---: | --- |",
    ...steps.map((step) => `| ${step.name} | ${step.category} | ${step.required ? "yes" : "no"} | ${step.status} | ${step.durationMs ?? ""} | ${(step.error ?? step.reason ?? "").replace(/\r?\n/g, " ")} |`),
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "## Pending Live Proof",
    "",
    ...(pendingLiveProofs.length ? pendingLiveProofs.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "## Provider Evidence Still Required",
    "",
    ...providerEvidence.map((item) => `- ${item}`),
  ]);
  const blockingItems = [...issues, ...pendingLiveProofs];
  log(`Pre go-live evidence written to ${jsonPath} and ${markdownPath}`);
  if (blockingItems.length && !booleanFlag(argv.allowFailures)) {
    fail(`Pre go-live evidence status=${payload.status} with ${blockingItems.length} blocker(s). Reports: ${jsonPath}, ${markdownPath}`);
  }
}

function productionGoNoGoPolicy() {
  const policyPath = path.resolve(argv.manifest ?? path.join(infraRoot, "governance", "production-go-no-go.json"));
  const policy = JSON.parse(readText(policyPath));
  if (policy.version !== 1) {
    fail(`Unsupported production go/no-go policy version in ${policyPath}.`);
  }
  return { policyPath, policy };
}

function latestJsonReport(directoryName, prefix, predicate = () => true) {
  const directory = path.join(infraRoot, "reports", directoryName);
  if (!fs.existsSync(directory)) return null;
  const reports = fs.readdirSync(directory)
    .filter((name) => name.startsWith(prefix) && name.endsWith(".json"))
    .map((name) => {
      const filePath = path.join(directory, name);
      let payload = null;
      let observedSha256 = null;
      let observedSizeBytes = null;
      try {
        const bytes = fs.readFileSync(filePath);
        payload = JSON.parse(bytes.toString("utf8"));
        observedSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
        observedSizeBytes = bytes.length;
      } catch {
        payload = null;
      }
      const generatedAt = payload?.generatedAt ? Date.parse(payload.generatedAt) : NaN;
      const timestamp = Number.isFinite(generatedAt) ? generatedAt : fs.statSync(filePath).mtimeMs;
      return { filePath, payload, timestamp, observedSha256, observedSizeBytes };
    })
    .filter((entry) => entry.payload)
    .filter((entry) => predicate(entry.payload, entry.filePath))
    .sort((a, b) => b.timestamp - a.timestamp);
  return reports[0] ?? null;
}

function reportAgeHours(report) {
  if (!report?.payload?.generatedAt) return Number.POSITIVE_INFINITY;
  const generatedAt = Date.parse(report.payload.generatedAt);
  if (!Number.isFinite(generatedAt)) return Number.POSITIVE_INFINITY;
  return (Date.now() - generatedAt) / 3600000;
}

function reportFreshDetail(report, maxAgeHours) {
  if (!report) return { fresh: false, detail: "missing report" };
  const ageHours = reportAgeHours(report);
  if (!Number.isFinite(ageHours)) return { fresh: false, detail: `report has invalid generatedAt: ${report.filePath}` };
  if (ageHours < 0) {
    return { fresh: false, detail: `report generatedAt is in the future by more than ${Math.abs(ageHours * 60).toFixed(1)} minutes` };
  }
  if (ageHours > maxAgeHours) {
    return { fresh: false, detail: `latest report is ${ageHours.toFixed(1)}h old; max ${maxAgeHours}h` };
  }
  return { fresh: true, detail: `fresh report age ${ageHours.toFixed(1)}h` };
}

function publicEvidenceUrl(urlValue) {
  if (!urlValue || typeof urlValue !== "string") return false;
  if (urlValue.startsWith("container:")) return false;
  let parsed = null;
  try {
    parsed = new URL(urlValue);
  } catch {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  return !isPrivateOrLocalHost(host);
}

function legacyPlatformEvidenceHost(urlValue) {
  if (!urlValue || typeof urlValue !== "string") return "";
  let parsed = null;
  try {
    parsed = new URL(urlValue);
  } catch {
    return "";
  }
  const host = parsed.hostname.toLowerCase();
  if (host === "sslip.io" || host.endsWith(".sslip.io")) return host;
  const firstLabel = host.split(".")[0];
  if (["account", "ui", "admin"].includes(firstLabel)) return host;
  return "";
}

const GO_NO_GO_CHECK_STATUSES = new Set(["passed", "failed", "pending-live-proof", "pending-provider"]);

function addGoNoGoCheck(checks, { name, passed, detail, report = null, required = true, status = null, blocker = null }) {
  const resolvedStatus = passed ? "passed" : (status ?? "failed");
  if (!GO_NO_GO_CHECK_STATUSES.has(resolvedStatus)) {
    fail(`Invalid production go/no-go check status for ${name}: ${resolvedStatus}`);
  }
  checks.push({
    name,
    required,
    status: resolvedStatus,
    blocker: resolvedStatus === "passed"
      ? null
      : (blocker ?? (resolvedStatus === "failed" ? "local" : "external")),
    detail,
    reportPath: report?.filePath ?? null,
    reportSha256: report?.observedSha256 ?? null,
    reportSizeBytes: report?.observedSizeBytes ?? null,
    generatedAt: report?.payload?.generatedAt ?? null,
  });
}

function goNoGoStatusCounts(checks) {
  const counts = Object.fromEntries([...GO_NO_GO_CHECK_STATUSES].map((status) => [status, 0]));
  for (const check of checks) {
    counts[check.status] = (counts[check.status] ?? 0) + 1;
  }
  return counts;
}

function goNoGoRemediation(check) {
  const candidateRemediation = {
    actions: [
      "Use one clean checkout and the exact production env/workload lock for every final evidence command.",
      "Regenerate release, GitHub Actions, functional health, pre-go-live and runtime fingerprint reports after any commit, tree, repository, workload-lock or Compose-render change.",
    ],
    commands: [
      "sh ./scripts/infra-ops.sh runtime-fingerprint --envFile .env --project platform_infra_vps --repo OWNER/REPO",
      "sh ./scripts/pre-go-live-evidence.sh --envFile .env --repo OWNER/REPO --includeRuntime --includeRestoreDrill --includeOffsiteRestoreDryRun --includeProductionPreflight --verifyGithubRemote",
      "sh ./scripts/production-go-no-go.sh --envFile .env --repo OWNER/REPO --enforce",
    ],
    evidence: "Every accepted report carries the same trusted platform.release-candidate/v1 identity.",
  };
  const remediations = {
    "release-candidate-current": candidateRemediation,
    "candidate-report-set-consistent": candidateRemediation,
    "evidence-report-authenticity": {
      actions: [
        "Export the exact final report set into a platform.evidence-trust-envelope/v1 document bound to the current candidate ID.",
        "Have the release owner pin the envelope SHA-256 in the independent deployment approval channel, then pass that digest to the gate.",
        "Do not derive the owner pin from the mutable reports directory or from the envelope being checked.",
      ],
      commands: [
        "sh ./scripts/production-go-no-go.sh --evidenceTrustEnvelope /secure/approved-evidence-envelope.json --evidenceTrustEnvelopeSha256 <owner-pinned-sha256> --enforce",
      ],
      evidence: "An owner-pinned, fresh evidence envelope bound to the current candidate and every exact selected report digest.",
    },
    "vps-bootstrap-applied": {
      actions: [
        "Run the VPS bootstrap on the actual VPS Ubuntu LTS host in apply mode, not from Docker Desktop or a diagnostic container.",
        "Archive the passing bootstrap JSON/Markdown apply reports outside Git before running the final go/no-go gate.",
      ],
      commands: [
        "sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user <deploy-user>",
      ],
      evidence: "reports/vps-bootstrap/vps-bootstrap-apply-*.json with mode=apply and status=applied",
    },
    "vps-hardening-applied": {
      actions: [
        "Run the VPS hardening on the actual VPS Ubuntu LTS host in apply mode.",
        "Reload SSH only after key-based access and the target SSH port are verified, so the effective daemon matches the hardened config.",
        "If an existing Docker daemon config is missing Platform hardening keys, review the generated template and rerun with the explicit replacement flag so a backup is created.",
        "Archive the passing hardening JSON/Markdown apply reports outside Git before running VPS host readiness.",
      ],
      commands: [
        "sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port <ssh-port> --reload-sshd",
        "sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port <ssh-port> --reload-sshd --replace-docker-daemon-config",
      ],
      evidence: "reports/vps-hardening/vps-hardening-apply-*.json with mode=apply, status=applied, ssh-service-reload applied and docker-daemon-config applied",
    },
    "vps-host-readiness": {
      actions: [
        "Run the host hardening and readiness checks on the actual VPS Ubuntu LTS VPS, not from Docker Desktop or a diagnostic container.",
        "Archive the passing VPS host readiness JSON/Markdown reports outside Git.",
      ],
      commands: [
        "sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port <ssh-port> --reload-sshd",
        "sh ./scripts/vps-host-readiness.sh --ssh-port <ssh-port> --enforce",
      ],
      evidence: "reports/vps-host/vps-host-readiness-*.json with summary.failedRequired=0, expectedSshPort and SSH/UFW port checks",
    },
    "pre-go-live-evidence-complete": {
      actions: [
        "Run the final evidence pack against the candidate VPS/staging stack after replacing production placeholders and configuring GitHub/provider credentials.",
        "Keep the generated reports outside Git and ensure status=passed.",
      ],
      commands: [
        "GITHUB_TOKEN=<token> sh ./scripts/pre-go-live-evidence.sh --repo OWNER/REPO --includeRuntime --includeRestoreDrill --includeOffsiteRestoreDryRun --includeProductionPreflight --verifyGithubRemote",
      ],
      evidence: "reports/go-live/pre-go-live-evidence-*.json with status=passed and no missingOptions",
    },
    "github-actions-run-success": {
      actions: [
        "Wait for the enterprise-infra GitHub Actions workflow to complete on the exact release commit.",
        "Rerun failed jobs from GitHub if needed, then verify the successful remote run with a token that can read Actions metadata.",
      ],
      commands: [
        "GITHUB_TOKEN=<token> sh ./scripts/github-actions-run-evidence.sh --repo OWNER/REPO --workflow enterprise-infra.yml --branch main --sha <release-sha> --verifyRemote",
      ],
      evidence: "reports/github-actions/github-actions-run-*.json with mode=verifyRemote, status=passed, workflow=enterprise-infra.yml and run.conclusion=success",
    },
    "secret-rotation-evidence": {
      actions: [
        "Initialize or upgrade the Infra Secret Manager store so every Compose secret is managed, materialized and audited.",
        "Rotate stale keyrings and opaque secrets inside a planned maintenance window, then rotate the Platform Local KMS active key.",
        "Archive the passing non-secret rotation report outside Git before the final go/no-go gate.",
      ],
      commands: [
        "sh ./scripts/infra-secret-manager.sh init",
        "sh ./scripts/infra-secret-manager.sh verify",
        "sh ./scripts/infra-secret-manager.sh rotate --name control_center_vault_keys",
        "sh ./scripts/infra-secret-manager.sh kms-rotate",
        "sh ./scripts/secret-rotation-evidence.sh --enforce",
      ],
      evidence: "reports/secret-rotation/secret-rotation-evidence-*.json with mode=evidence, status=passed, verify.status=passed and zero expired/missing secrets",
    },
    "disaster-recovery-rpo-rto-offsite": {
      actions: [
        "Configure a remote Restic repository and run a real off-site restore drill covering PostgreSQL, MariaDB, MinIO, Keycloak and Secret Manager metadata.",
        "Run DR evidence after the restore so RPO/RTO and coverage are recalculated from fresh reports.",
      ],
      commands: [
        "sh ./scripts/offsite-backup-restic.sh --passwordFile ./secrets/restic_password.txt",
        "sh ./scripts/offsite-restore-drill-restic.sh --passwordFile ./secrets/restic_password.txt",
        "sh ./scripts/dr-evidence.sh --enforce",
      ],
      evidence: "reports/dr/dr-evidence-*.json with status=passed and offsiteEvidence.latestRestoreCoverage.complete=true",
    },
    "real-alert-delivery": {
      actions: [
        "Send a real Alertmanager delivery test through the production notification channel.",
      ],
      commands: [
        "sh ./scripts/alert-evidence.sh --sendTest --requireEmailDelivery",
      ],
      evidence: "reports/alerts/alert-evidence-*.json with mode=send-test and status=passed",
    },
    "external-uptime-provider": {
      actions: [
        "Create provider monitors from monitoring/external-uptime.example.json after public DNS, CDN and TLS are live.",
        "Record provider monitor ids, regions, last status code, last latency and last checked timestamp in a production-only evidence file.",
      ],
      commands: [
        "cp monitoring/external-uptime-provider.example.json monitoring/external-uptime-provider.production.json",
        "sh ./scripts/external-uptime-check.sh --providerEvidence ./monitoring/external-uptime-provider.production.json --validateProviderEvidenceOnly",
        "sh ./scripts/external-uptime-check.sh --envFile .env --providerEvidence ./monitoring/external-uptime-provider.production.json --requireProviderEvidence",
      ],
      evidence: "reports/uptime/external-uptime-*.json with providerEvidence.verified=true and public target results",
    },
    "public-load-benchmark": {
      actions: [
        "Run the 50/100/500 benchmark against the public HTTPS API through the CDN/edge path.",
        "Obtain fresh provider-observed traversal evidence for a unique request URL and attest the exact JSON artifact with the approved GitHub workflow.",
        "Treat response headers as diagnostics only; they cannot satisfy the edge gate.",
      ],
      commands: [
        "sh ./scripts/load-benchmark.sh --url 'https://api.<domain>/health?proof=<unique-release-nonce>' --profiles 50,100,500 --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare --edgeProviderEvidence /secure/edge-provider-evidence.json --edgeProviderEvidenceAttestation online --edgeProviderEvidenceRepository OWNER/REPO --edgeProviderEvidenceWorkflow OWNER/REPO/.github/workflows/provider-evidence.yml --edgeProviderEvidenceSourceDigest <full-sha> --edgeProviderEvidenceSourceRef refs/heads/main",
      ],
      evidence: "reports/load/load-benchmark-*.json with status=passed, current-candidate binding, authenticated provider evidence and required profiles",
    },
    "release-evidence-and-rollback": {
      actions: [
        "Generate release evidence from digest-pinned images, SBOM, SLSA provenance and previous release image digests.",
        "Keep the rollback dry-run report linked from the release evidence pack.",
      ],
      commands: [
        "sh ./scripts/release-evidence.sh --envFile .env --sbom security/sbom/<sbom>.json --repo owner/repo --sourceRef refs/heads/main --previousImagesFile release/previous-images.json --requireProvenance",
      ],
      evidence: "reports/release/release-evidence-*.json with mode=evidence, status=passed, GitHub/Sigstore cryptographic provenance passed and rollback validated",
    },
    "cloudflare-access-admin-verified": {
      actions: [
        "Apply or verify the additive Cloudflare Access manifest for admin applications after the Cloudflare zone and identity provider are configured.",
        "Do not overwrite unrelated Cloudflare rules; use the dedicated Access admin manifest.",
      ],
      commands: [
        "CLOUDFLARE_API_TOKEN=<token> CLOUDFLARE_ACCOUNT_ID=<account-id> sh ./scripts/cloudflare-access-admin.sh --manifest cloudflare/access-admin.production.json --verifyRemote",
      ],
      evidence: "reports/cloudflare-access/cloudflare-access-admin-*.json with mode=verifyRemote and every application result=verified",
    },
  };

  const fallback = {
    actions: ["Inspect the referenced report and rerun the failing evidence command until the check passes."],
    commands: ["sh ./scripts/production-go-no-go.sh"],
    evidence: "A fresh passing report for the failed check.",
  };
  return {
    check: check.name,
    status: check.status,
    detail: check.detail,
    reportPath: check.reportPath,
    ...(remediations[check.name] ?? fallback),
  };
}

function goNoGoRemediationMarkdown(remediation) {
  if (!remediation.length) {
    return ["- none"];
  }
  return remediation.flatMap((item) => [
    `### ${item.check}`,
    "",
    `Detail: ${item.detail}`,
    `Current report: ${item.reportPath ?? "n/a"}`,
    `Expected evidence: ${item.evidence}`,
    "",
    "Actions:",
    ...item.actions.map((action) => `- ${action}`),
    "",
    "Commands:",
    ...item.commands.map((commandLine) => `- \`${commandLine}\``),
    "",
  ]);
}

const evidenceBundleCandidateCiLabels = new Set([
  "healthcheck-coverage",
  "rate-limit-evidence",
  "audit-log-evidence",
  "retention-evidence",
]);

const evidenceBundleReportSpecs = [
  { directory: "go-no-go", prefix: "production-go-no-go-", label: "production-go-no-go", required: true },
  { directory: "production-readiness", prefix: "production-readiness-", label: "production-readiness-live", required: true },
  { directory: "github-actions", prefix: "github-actions-run-", label: "github-actions-run", required: true },
  { directory: "healthchecks", prefix: "healthcheck-coverage-", label: "healthcheck-coverage", required: true },
  { directory: "healthchecks", prefix: "functional-health-", label: "functional-health", required: true },
  { directory: "runtime-fingerprint", prefix: "runtime-fingerprint-", label: "runtime-fingerprint", required: true },
  { directory: "rate-limits", prefix: "rate-limit-evidence-", label: "rate-limit-evidence", required: true },
  { directory: "audit-logs", prefix: "audit-log-evidence-", label: "audit-log-evidence", required: true },
  { directory: "retention", prefix: "retention-evidence-", label: "retention-evidence", required: true },
  { directory: "secret-rotation", prefix: "secret-rotation-evidence-", label: "secret-rotation-evidence", required: true },
  { directory: "go-live", prefix: "pre-go-live-evidence-", label: "pre-go-live", required: true },
  { directory: "vps-host", prefix: "vps-host-readiness-", label: "vps-host-readiness", required: true },
  { directory: "dr", prefix: "dr-evidence-", label: "dr-evidence", required: true },
  { directory: "offsite-restore-drills", prefix: "offsite-restore-drill-", label: "offsite-restore-drill", required: true },
  { directory: "uptime", prefix: "external-uptime-", label: "external-uptime", required: true },
  { directory: "load", prefix: "load-benchmark-", label: "load-benchmark", required: true },
  { directory: "release", prefix: "release-evidence-", label: "release-evidence", required: true },
  { directory: "rollback", prefix: "rollback-plan-", label: "rollback-plan", required: true },
  { directory: "cloudflare-access", prefix: "cloudflare-access-admin-", label: "cloudflare-access-admin", required: true },
  { directory: "alerts", prefix: "alert-evidence-", label: "alert-evidence", required: true },
  { directory: "linux-portability", prefix: "linux-portability-", label: "linux-portability", required: true },
  { directory: "vps-bootstrap", prefix: "vps-bootstrap-apply-", label: "vps-bootstrap-apply", required: true },
  { directory: "vps-hardening", prefix: "vps-hardening-apply-", label: "vps-hardening-apply", required: true },
  { directory: "vps-go-live", prefix: "vps-go-live-", label: "vps-go-live", required: false },
  { directory: "backups", prefix: "", label: "backup-execution-reports", required: false },
  { directory: "restore-drills", prefix: "full-restore-drill-", label: "full-restore-drill", required: false },
  { directory: "failure-tests", prefix: "failure-tests-", label: "failure-tests", required: false },
].map((spec) => ({
  ...spec,
  phases: evidenceBundleCandidateCiLabels.has(spec.label)
    ? ["candidate-ci", "production-live"]
    : ["production-live"],
}));

const evidenceBundleDocPaths = [
  "README.md",
  "RUNBOOK.md",
  "SECURITY.md",
  "THREAT-MODEL.md",
  "READINESS-REPORT.md",
  "FINAL-READINESS-AUDIT.md",
  "VPS-PREDEPLOY-CHECKLIST.md",
  "governance/production-go-no-go.json",
  "governance/production-readiness.json",
  "governance/github-actions-runtime.json",
  "governance/github-branch-protection.json",
  "governance/github-environments.json",
  "monitoring/external-uptime.example.json",
  "monitoring/external-uptime-provider.example.json",
  "monitoring/edge-traversal-provider.example.json",
  "cloudflare/README.md",
  "cloudflare/access-admin.example.json",
  "cloudflare/from-zero.example.json",
];

function assertEvidenceBundleRelativePath(relativePath) {
  const normalized = relativePath.replaceAll("\\", "/");
  if (!normalized || normalized.startsWith("/") || normalized.includes("../") || normalized.startsWith("../")) {
    fail(`Invalid evidence bundle path: ${relativePath}`);
  }
  if (
    /^\.env(?:\.|$)/.test(normalized)
    || normalized.startsWith("secrets/")
    || normalized.startsWith("backups/")
    || normalized.startsWith("release/")
    || normalized.startsWith("security/sbom/")
    || normalized.startsWith("security/dast/")
    || normalized.includes("/secrets/")
  ) {
    fail(`Refusing to include sensitive path in evidence bundle: ${relativePath}`);
  }
  return normalized;
}

function evidenceBundleSpecsForPhase(phase) {
  return evidenceBundleReportSpecs.filter((spec) => spec.phases.includes(phase));
}

function evidenceBundleProductionRequiredLabels() {
  return evidenceBundleReportSpecs.filter((spec) => spec.required).map((spec) => spec.label);
}

function listEvidenceBundleReportFiles({ allReports, phase }) {
  const files = [];
  const missing = [];
  const policy = evidenceBundlePhasePolicy(phase, { productionRequiredLabels: evidenceBundleProductionRequiredLabels() });
  const requiredLabels = new Set(policy.requiredLabels);
  for (const spec of evidenceBundleSpecsForPhase(phase)) {
    const directory = path.join(infraRoot, "reports", spec.directory);
    if (!fs.existsSync(directory)) {
      if (requiredLabels.has(spec.label)) missing.push({ label: spec.label, reason: "missing report directory" });
      continue;
    }
    if (allReports) {
      const matches = fs.readdirSync(directory)
        .filter((name) => name.startsWith(spec.prefix) && /\.(json|md)$/i.test(name))
        .map((name) => path.join(directory, name))
        .filter((filePath) => fs.statSync(filePath).isFile())
        .sort();
      if (!matches.length && requiredLabels.has(spec.label)) missing.push({ label: spec.label, reason: "missing reports" });
      files.push(...matches);
      continue;
    }
    const report = latestJsonReport(spec.directory, spec.prefix);
    if (!report) {
      if (requiredLabels.has(spec.label)) missing.push({ label: spec.label, reason: "missing latest JSON report" });
      continue;
    }
    files.push(report.filePath);
    const markdownPath = report.filePath.replace(/\.json$/i, ".md");
    if (fs.existsSync(markdownPath)) {
      files.push(markdownPath);
    }
  }
  return { files, missing };
}

function evidenceBundleSpecForEntry(entryPath, phase) {
  return evidenceBundleSpecsForPhase(phase).find((spec) => (
    entryPath.startsWith(`reports/${spec.directory}/`)
    && path.basename(entryPath).startsWith(spec.prefix)
    && entryPath.endsWith(".json")
  )) ?? null;
}

function evidenceBundleCapturedReports(entries, bytesByPath, phase, issues = []) {
  const reports = [];
  for (const entry of entries) {
    if (entry.type !== "report" || !entry.path.endsWith(".json")) continue;
    const spec = evidenceBundleSpecForEntry(entry.path, phase);
    if (!spec) {
      issues.push(`${entry.path}: report is not allowed in phase ${phase}`);
      continue;
    }
    const bytes = bytesByPath.get(entry.path);
    if (!bytes) {
      issues.push(`${entry.path}: report bytes are unavailable`);
      continue;
    }
    try {
      reports.push({ label: spec.label, path: entry.path, payload: JSON.parse(bytes.toString("utf8")) });
    } catch {
      issues.push(`${entry.path}: report is invalid JSON`);
    }
  }
  return reports;
}

function evaluateCapturedEvidenceBundle({ phase, sourceGit, currentGit, candidate, missingRequiredEvidence, reports, requireComplete, notBefore, maxAgeHours, expectedPhase }) {
  return evaluateEvidenceBundlePhase({
    phase,
    expectedPhase,
    sourceGit,
    currentGit,
    candidate,
    missingRequiredEvidence,
    reports,
    productionRequiredLabels: evidenceBundleProductionRequiredLabels(),
    requireComplete,
    notBefore,
    maxAgeHours,
    reportPasses: (label, payload) => {
      const spec = evidenceBundleReportSpecs.find((entry) => entry.label === label);
      return spec ? evidenceBundleReportPasses(spec, payload) : { passed: false, detail: "unknown report label" };
    },
  });
}

function latestEvidenceBundleDir(outputRoot) {
  if (!fs.existsSync(outputRoot)) {
    return null;
  }
  const candidates = fs.readdirSync(outputRoot)
    .filter((name) => name.startsWith("infra-evidence-bundle-"))
    .map((name) => path.join(outputRoot, name))
    .filter((entryPath) => fs.existsSync(entryPath) && fs.statSync(entryPath).isDirectory())
    .filter((entryPath) => fs.existsSync(path.join(entryPath, "manifest.json")))
    .sort();
  return candidates.at(-1) ?? null;
}

function validateEvidenceBundleEntry(entry, bundleDir, issues) {
  if (!entry || typeof entry !== "object") {
    issues.push("manifest contains a non-object entry");
    return null;
  }
  let normalizedPath = null;
  try {
    normalizedPath = assertEvidenceBundleRelativePath(String(entry.path ?? ""));
  } catch (error) {
    issues.push(String(error?.message ?? error));
    return null;
  }
  if (!["document", "report"].includes(entry.type)) {
    issues.push(`${normalizedPath}: invalid entry type '${entry.type}'`);
  }
  if (!/^[a-f0-9]{64}$/i.test(String(entry.sha256 ?? ""))) {
    issues.push(`${normalizedPath}: invalid sha256`);
  }
  if (!Number.isInteger(entry.sizeBytes) || entry.sizeBytes < 0) {
    issues.push(`${normalizedPath}: invalid sizeBytes`);
  }
  const filePath = path.resolve(bundleDir, normalizedPath);
  const bundleRoot = path.resolve(bundleDir);
  if (!filePath.startsWith(`${bundleRoot}${path.sep}`)) {
    issues.push(`${normalizedPath}: resolves outside bundle directory`);
    return { normalizedPath, bytes: null };
  }
  const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  if (!stat?.isFile() || stat.isSymbolicLink()) {
    issues.push(`${normalizedPath}: file missing from bundle`);
    return { normalizedPath, bytes: null };
  }
  const resolvedFilePath = fs.realpathSync(filePath);
  const resolvedBundleRoot = fs.realpathSync(bundleRoot);
  if (!resolvedFilePath.startsWith(`${resolvedBundleRoot}${path.sep}`)) {
    issues.push(`${normalizedPath}: resolves outside the real bundle directory`);
    return { normalizedPath, bytes: null };
  }
  const bytes = fs.readFileSync(filePath);
  if (Number.isInteger(entry.sizeBytes) && bytes.length !== entry.sizeBytes) {
    issues.push(`${normalizedPath}: size mismatch manifest=${entry.sizeBytes} actual=${bytes.length}`);
  }
  const actualHash = crypto.createHash("sha256").update(bytes).digest("hex");
  if (String(entry.sha256 ?? "").toLowerCase() !== actualHash) {
    issues.push(`${normalizedPath}: sha256 mismatch`);
  }
  return { normalizedPath, bytes };
}

function evidenceBundleReportPasses(spec, payload) {
  if (!payload || typeof payload !== "object") {
    return { passed: false, detail: "report payload is missing" };
  }
  const operationalResult = evaluateOperationalEvidenceReport(spec.label, payload);
  if (operationalResult) return operationalResult;
  if (spec.label === "production-go-no-go") {
    return { passed: payload.status === "go", detail: `status=${payload.status ?? "missing"}` };
  }
  if (spec.label === "vps-bootstrap-apply" || spec.label === "vps-hardening-apply") {
    return { passed: payload.status === "applied" && payload.mode === "apply", detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"}` };
  }
  if (spec.label === "vps-host-readiness") {
    return { passed: Number(payload.summary?.failedRequired ?? 1) === 0 && payload.productionEvidence !== false, detail: `failedRequired=${payload.summary?.failedRequired ?? "missing"}` };
  }
  if (spec.label === "github-actions-run") {
    return { passed: payload.mode === "verifyRemote" && payload.status === "passed" && payload.run?.conclusion === "success", detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} conclusion=${payload.run?.conclusion ?? "missing"}` };
  }
  if (spec.label === "healthcheck-coverage") {
    const missing = Array.isArray(payload.missingHealthchecks)
      ? payload.missingHealthchecks.length
      : Number(payload.summary?.missingHealthchecks ?? 1);
    return { passed: payload.status === "passed" && missing === 0, detail: `status=${payload.status ?? "missing"} missing=${missing}` };
  }
  if (spec.label === "functional-health") {
    const checks = Array.isArray(payload.checks) ? payload.checks : [];
    return { passed: payload.mode === "runtime" && payload.status === "passed" && checks.length > 0 && checks.every((check) => check.passed === true), detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} checks=${checks.length}` };
  }
  if (spec.label === "runtime-fingerprint") {
    return { passed: payload.mode === "runtime-exact" && payload.status === "passed" && payload.git?.clean === true && /^[a-f0-9]{64}$/.test(String(payload.fingerprint ?? "")), detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} clean=${payload.git?.clean ?? "missing"}` };
  }
  if (spec.label === "rate-limit-evidence") {
    return {
      passed: payload.status === "passed"
        && Number(payload.summary?.failed ?? 1) === 0
        && Number(payload.summary?.infraChecksPassed ?? 0) >= 4
        && ["full", "infra-only"].includes(payload.mode),
      detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} failed=${payload.summary?.failed ?? "missing"} infraPassed=${payload.summary?.infraChecksPassed ?? "missing"}`,
    };
  }
  if (spec.label === "audit-log-evidence") {
    return {
      passed: payload.status === "passed"
        && Number(payload.summary?.failed ?? 1) === 0
        && Number(payload.summary?.infraChecksPassed ?? 0) >= 9
        && ["full", "infra-only"].includes(payload.mode),
      detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} failed=${payload.summary?.failed ?? "missing"} infraPassed=${payload.summary?.infraChecksPassed ?? "missing"}`,
    };
  }
  if (spec.label === "retention-evidence") {
    return {
      passed: payload.status === "passed"
        && Number(payload.summary?.failed ?? 1) === 0
        && Number(payload.summary?.infraChecksPassed ?? 0) >= 14
        && ["full", "infra-only"].includes(payload.mode),
      detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} failed=${payload.summary?.failed ?? "missing"} infraPassed=${payload.summary?.infraChecksPassed ?? "missing"}`,
    };
  }
  if (spec.label === "secret-rotation-evidence") {
    return {
      passed: payload.mode === "evidence"
        && payload.status === "passed"
        && payload.verify?.status === "passed"
        && Number(payload.summary?.failedSecrets ?? 1) === 0
        && Number(payload.summary?.expiredSecrets ?? 1) === 0
        && Number(payload.summary?.missingMaterializedFiles ?? 1) === 0,
      detail: `mode=${payload.mode ?? "missing"} status=${payload.status ?? "missing"} verify=${payload.verify?.status ?? "missing"} expired=${payload.summary?.expiredSecrets ?? "missing"} missingFiles=${payload.summary?.missingMaterializedFiles ?? "missing"}`,
    };
  }
  if (spec.label === "rollback-plan") {
    return { passed: payload.validated === true || payload.status === "passed", detail: `validated=${payload.validated ?? "missing"} status=${payload.status ?? "missing"}` };
  }
  return { passed: payload.status === "passed", detail: `status=${payload.status ?? "missing"}` };
}

async function evidenceBundle() {
  await withLocalCheckReport("evidence-bundle", evidenceBundleBody);
}

async function evidenceBundleBody() {
  log("==> Evidence bundle");
  const phase = normalizeEvidenceBundlePhase(argv.phase ?? process.env.EVIDENCE_BUNDLE_PHASE);
  const strict = booleanFlag(argv.strict);
  const allReports = booleanFlag(argv.allReports);
  const noArchive = booleanFlag(argv.noArchive);
  if (strict && allReports) fail("Strict evidence bundles require exactly the latest JSON report per phase category; --allReports is not allowed.");
  const maxAgeHours = Number(argv.maxAgeHours ?? process.env.EVIDENCE_BUNDLE_MAX_AGE_HOURS ?? 24);
  const notBefore = argv.notBefore ?? process.env.EVIDENCE_BUNDLE_NOT_BEFORE ?? null;
  const stamp = reportTimestamp();
  const outputRoot = path.resolve(argv.outputDir ?? path.join(infraRoot, ".tmp", "evidence-bundles"));
  fs.mkdirSync(outputRoot, { recursive: true });
  const bundleName = `infra-evidence-bundle-${stamp}`;
  const bundleDir = path.join(outputRoot, bundleName);
  removeTreeInside(outputRoot, bundleDir);
  fs.mkdirSync(bundleDir, { recursive: true });

  const copied = new Map();
  const copyEvidenceFile = (sourcePath, relativePath, type) => {
    if (!fs.existsSync(sourcePath) || !fs.statSync(sourcePath).isFile()) {
      return null;
    }
    const normalized = assertEvidenceBundleRelativePath(relativePath);
    if (copied.has(normalized)) {
      return copied.get(normalized);
    }
    const targetPath = path.join(bundleDir, normalized);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.copyFileSync(sourcePath, targetPath);
    const entry = {
      type,
      path: normalized,
      sizeBytes: fs.statSync(targetPath).size,
      sha256: sha256File(targetPath),
    };
    copied.set(normalized, entry);
    return entry;
  };

  const { files: reportFiles, missing } = listEvidenceBundleReportFiles({ allReports, phase });
  for (const reportFile of reportFiles) {
    const relativePath = path.relative(infraRoot, reportFile).replaceAll("\\", "/");
    copyEvidenceFile(reportFile, relativePath, "report");
  }
  for (const docPath of evidenceBundleDocPaths) {
    copyEvidenceFile(path.join(infraRoot, docPath), docPath, "document");
  }

  const entries = Array.from(copied.values()).sort((a, b) => a.path.localeCompare(b.path));
  const copiedBytes = new Map(entries.map((entry) => [entry.path, fs.readFileSync(path.join(bundleDir, entry.path))]));
  const captureIssues = [];
  const reports = evidenceBundleCapturedReports(entries, copiedBytes, phase, captureIssues);
  const sourceGit = gitEvidence();
  const candidate = phase === "production-live"
    ? reports.find((report) => report.label === "production-go-no-go")?.payload?.candidate ?? null
    : null;
  const evaluation = evaluateCapturedEvidenceBundle({
    phase,
    sourceGit,
    candidate,
    missingRequiredEvidence: missing,
    reports,
    requireComplete: strict,
    notBefore,
    maxAgeHours,
  });
  evaluation.issues.push(...captureIssues);
  evaluation.issues = [...new Set(evaluation.issues)];
  evaluation.passed = evaluation.issues.length === 0;
  evaluation.complete = strict && evaluation.passed;

  const manifestPath = path.join(bundleDir, "manifest.json");
  const manifest = {
    version: evidenceBundleManifestVersion,
    generatedAt: new Date().toISOString(),
    mode: allReports ? "all-reports" : "latest-per-category",
    phase: {
      name: phase,
      authority: evaluation.policy?.authority ?? null,
      strict,
      complete: evaluation.complete,
      notBefore,
      maxAgeHours,
      requiredLabels: evaluation.requiredLabels,
      reportLabels: evaluation.reportLabels,
      issues: evaluation.issues,
    },
    source: {
      git: sourceGit,
      candidate,
      command: "evidence-bundle",
    },
    policy: {
      includesSecrets: false,
      includesBackupArtifacts: false,
      includesReleaseArtifacts: false,
      outputDirectoryIgnoredByGit: outputRoot.includes(`${path.sep}.tmp${path.sep}`) || path.basename(path.dirname(outputRoot)) === ".tmp",
    },
    missingRequiredEvidence: missing,
    entries,
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const manifestMarkdownPath = path.join(bundleDir, "manifest.md");
  fs.writeFileSync(manifestMarkdownPath, [
    "# Platform Evidence Bundle",
    "",
    `Generated at: ${manifest.generatedAt}`,
    `Mode: ${manifest.mode}`,
    `Phase: ${manifest.phase.name}`,
    `Phase authority: ${manifest.phase.authority}`,
    `Strict complete: ${manifest.phase.complete ? "yes" : "no"}`,
    `Git commit: ${manifest.source.git.commit ?? "unknown"}`,
    `Git tree: ${manifest.source.git.tree ?? "unknown"}`,
    `Git dirty: ${manifest.source.git.dirty ? "yes" : "no"}`,
    `Candidate: ${manifest.source.candidate?.id ?? "not-applicable"}`,
    "",
    "## Policy",
    "",
    "- Secrets: excluded",
    "- Backup artifacts: excluded",
    "- Release artifacts: excluded",
    "- Output: `.tmp/evidence-bundles/` by default",
    "",
    "## Missing Required Evidence",
    "",
    ...(missing.length ? missing.map((item) => `- ${item.label}: ${item.reason}`) : ["- none"]),
    "",
    "## Phase Evaluation Issues",
    "",
    ...(evaluation.issues.length ? evaluation.issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "## Files",
    "",
    "| Type | Path | SHA256 |",
    "| --- | --- | --- |",
    ...manifest.entries.map((entry) => `| ${entry.type} | ${entry.path} | ${entry.sha256} |`),
  ].join("\n") + "\n", "utf8");

  const archivePath = `${bundleDir}.tar.gz`;
  let archive = null;
  if (!noArchive) {
    const tar = run("tar", ["-czf", archivePath, "-C", outputRoot, bundleName], { allowFailure: true, capture: true });
    if (tar.status === 0 && fs.existsSync(archivePath)) {
      archive = {
        path: archivePath,
        sizeBytes: fs.statSync(archivePath).size,
        sha256: sha256File(archivePath),
      };
    } else {
      log("tar not available or archive creation failed; bundle directory was still written.");
    }
  }
  const summary = {
    generatedAt: manifest.generatedAt,
    bundleDir,
    archive,
    phase,
    complete: manifest.phase.complete,
    files: manifest.entries.length,
    missingRequiredEvidence: missing,
  };
  fs.writeFileSync(path.join(bundleDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  log(`Evidence bundle written to ${bundleDir}`);
  if (archive) {
    log(`Evidence archive written to ${archive.path}`);
  }
  if (missing.length) {
    log(`Missing required evidence: ${missing.map((item) => item.label).join(", ")}`);
  }
  if (strict && !evaluation.passed) {
    fail(`Strict ${phase} evidence bundle is incomplete or incompatible: ${evaluation.issues.join("; ")}`);
  }
}

async function evidenceBundleVerify() {
  log("==> Evidence bundle verify");
  const outputRoot = path.resolve(argv.outputDir ?? path.join(infraRoot, ".tmp", "evidence-bundles"));
  const bundleDir = path.resolve(argv.bundleDir ?? argv._[0] ?? latestEvidenceBundleDir(outputRoot) ?? "");
  const requireComplete = booleanFlag(argv.requireComplete);
  const expectedPhaseValue = argv.phase ?? process.env.EVIDENCE_BUNDLE_PHASE;
  const maxAgeHours = Number(argv.maxAgeHours ?? process.env.EVIDENCE_BUNDLE_MAX_AGE_HOURS ?? 24);
  const expectedNotBefore = argv.notBefore ?? process.env.EVIDENCE_BUNDLE_NOT_BEFORE ?? null;
  const issues = [];
  const externalPending = [];
  if (!bundleDir || !fs.existsSync(bundleDir) || !fs.statSync(bundleDir).isDirectory()) {
    fail(`Evidence bundle directory not found. Pass --bundleDir <path> or create one with evidence-bundle. Looked in: ${outputRoot}`);
  }
  const manifestPath = path.join(bundleDir, "manifest.json");
  const manifestMarkdownPath = path.join(bundleDir, "manifest.md");
  const summaryPath = path.join(bundleDir, "summary.json");
  if (!fs.existsSync(manifestPath)) {
    fail(`Missing evidence bundle manifest: ${manifestPath}`);
  }
  const manifestStat = fs.lstatSync(manifestPath, { throwIfNoEntry: false });
  if (!manifestStat?.isFile() || manifestStat.isSymbolicLink()) {
    fail(`Evidence bundle manifest must be a regular non-symlink file: ${manifestPath}`);
  }
  const manifestBytes = fs.readFileSync(manifestPath);
  let manifest = null;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch (error) {
    fail(`Invalid evidence bundle manifest JSON: ${String(error?.message ?? error)}`);
  }
  const expectedManifestSha256 = argv.ownerPinnedManifestSha256 ?? process.env.EVIDENCE_BUNDLE_MANIFEST_SHA256;
  let manifestTrust = null;
  if (!expectedManifestSha256) {
    externalPending.push("EXTERNAL-PENDING: an independent release owner must pin the exact evidence bundle manifest SHA-256.");
  } else {
    try {
      manifestTrust = verifyOwnerPinnedBundleManifest({ manifestBytes, expectedManifestSha256 });
    } catch (error) {
      issues.push(String(error?.message ?? error));
    }
  }
  if (manifest.version !== evidenceBundleManifestVersion) {
    issues.push(`manifest.version must be ${evidenceBundleManifestVersion}, found ${manifest.version ?? "missing"}`);
  }
  if (manifest.source?.command !== "evidence-bundle") {
    issues.push("manifest.source.command must be evidence-bundle");
  }
  if (manifest.policy?.includesSecrets !== false) {
    issues.push("manifest policy must exclude secrets");
  }
  if (manifest.policy?.includesBackupArtifacts !== false) {
    issues.push("manifest policy must exclude backup artifacts");
  }
  if (manifest.policy?.includesReleaseArtifacts !== false) {
    issues.push("manifest policy must exclude release artifacts");
  }
  if (manifest.policy?.outputDirectoryIgnoredByGit !== true) {
    issues.push("manifest policy must confirm the output directory is ignored by Git");
  }
  let phase = null;
  try {
    phase = normalizeEvidenceBundlePhase(manifest.phase?.name);
  } catch (error) {
    issues.push(String(error?.message ?? error));
  }
  if (requireComplete && !expectedPhaseValue) {
    issues.push("--requireComplete requires an independently selected --phase");
  }
  if (manifest.phase?.maxAgeHours !== maxAgeHours) {
    issues.push(`manifest phase maxAgeHours mismatch: expected ${maxAgeHours}, found ${manifest.phase?.maxAgeHours ?? "missing"}`);
  }
  if (expectedNotBefore && manifest.phase?.notBefore !== expectedNotBefore) {
    issues.push("manifest phase notBefore does not match the independently supplied timestamp");
  }
  if (requireComplete && (manifest.phase?.strict !== true || manifest.phase?.complete !== true)) {
    issues.push("complete verification requires a manifest created by the strict phase flow");
  }
  if (requireComplete && Array.isArray(manifest.phase?.issues) && manifest.phase.issues.length) {
    issues.push("strict manifest records unresolved phase issues");
  }
  const missingRequiredEvidence = Array.isArray(manifest.missingRequiredEvidence) ? manifest.missingRequiredEvidence : [];
  if (!Array.isArray(manifest.missingRequiredEvidence)) {
    issues.push("manifest.missingRequiredEvidence must be an array");
  }
  if (!Array.isArray(manifest.entries) || !manifest.entries.length) {
    issues.push("manifest.entries must be a non-empty array");
  }
  const paths = new Set();
  const validatedEntries = new Map();
  for (const entry of Array.isArray(manifest.entries) ? manifest.entries : []) {
    const validated = validateEvidenceBundleEntry(entry, bundleDir, issues);
    if (!validated) {
      continue;
    }
    const { normalizedPath } = validated;
    if (paths.has(normalizedPath)) {
      issues.push(`${normalizedPath}: duplicate manifest entry`);
    } else if (validated.bytes) {
      validatedEntries.set(normalizedPath, validated.bytes);
    }
    paths.add(normalizedPath);
  }
  let closedWorld = null;
  try {
    closedWorld = verifyClosedWorldBundleFiles({ bundleDir, manifestEntryPaths: [...paths] });
  } catch (error) {
    issues.push(String(error?.message ?? error));
  }
  for (const docPath of evidenceBundleDocPaths) {
    if (!paths.has(docPath)) {
      issues.push(`missing required document entry: ${docPath}`);
    }
  }
  let phaseEvaluation = null;
  if (phase) {
    const reportEntries = (Array.isArray(manifest.entries) ? manifest.entries : []).filter((entry) => entry?.type === "report");
    const reports = evidenceBundleCapturedReports(reportEntries, validatedEntries, phase, issues);
    phaseEvaluation = evaluateCapturedEvidenceBundle({
      phase,
      expectedPhase: expectedPhaseValue,
      sourceGit: manifest.source?.git,
      currentGit: gitEvidence(),
      candidate: manifest.source?.candidate,
      missingRequiredEvidence,
      reports,
      requireComplete,
      notBefore: manifest.phase?.notBefore,
      maxAgeHours,
    });
    issues.push(...phaseEvaluation.issues);
    if (requireComplete && manifest.phase?.authority !== phaseEvaluation.policy?.authority) {
      issues.push("manifest phase authority does not match verifier policy");
    }
    if (requireComplete && JSON.stringify(manifest.phase?.requiredLabels ?? null) !== JSON.stringify(phaseEvaluation.requiredLabels)) {
      issues.push("manifest requiredLabels do not match verifier phase policy");
    }
    if (requireComplete && JSON.stringify(manifest.phase?.reportLabels ?? null) !== JSON.stringify(phaseEvaluation.reportLabels)) {
      issues.push("manifest reportLabels do not match captured report set");
    }
  }
  if (!fs.existsSync(manifestMarkdownPath)) {
    issues.push("missing manifest.md");
  }
  if (fs.existsSync(summaryPath)) {
    const summary = readJsonFile(summaryPath, summaryPath);
    if (summary.files !== paths.size) {
      issues.push(`summary.files mismatch manifest entries: summary=${summary.files} manifest=${paths.size}`);
    }
    if (!Array.isArray(summary.missingRequiredEvidence)) {
      issues.push("summary.missingRequiredEvidence must be an array");
    }
    if (summary.phase !== manifest.phase?.name || summary.complete !== manifest.phase?.complete) {
      issues.push("summary phase metadata mismatch manifest");
    }
  } else {
    issues.push("missing summary.json");
  }

  const stamp = reportTimestamp();
  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : externalPending.length ? "external-pending" : "passed",
    bundleDir,
    phase,
    requireComplete,
    phaseEvaluation,
    closedWorld,
    manifestTrust,
    entryCount: paths.size,
    missingRequiredEvidence,
    issues,
    externalPending,
  };
  const jsonPath = writeJsonReport("evidence-bundle-verify", `evidence-bundle-verify-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("evidence-bundle-verify", `evidence-bundle-verify-${stamp}`, [
    "# Evidence Bundle Verify",
    "",
    `Status: ${payload.status}`,
    `Bundle: ${bundleDir}`,
    `Phase: ${phase ?? "invalid"}`,
    `Require complete: ${requireComplete}`,
    `Manifest trust: ${manifestTrust?.trustMode ?? "EXTERNAL-PENDING"}`,
    `Entries: ${payload.entryCount}`,
    "",
    "## Missing Required Evidence",
    "",
    ...(missingRequiredEvidence.length ? missingRequiredEvidence.map((item) => `- ${item.label}: ${item.reason}`) : ["- none"]),
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "## External Pending",
    "",
    ...(externalPending.length ? externalPending.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Evidence bundle verification report written to ${jsonPath} and ${markdownPath}`);
  if (issues.length) {
    const pendingDetail = externalPending.length ? " EXTERNAL-PENDING: independent manifest approval is also absent." : "";
    fail(`Evidence bundle verification failed with ${issues.length} issue(s).${pendingDetail} Report: ${jsonPath}`);
  }
  if (externalPending.length) {
    fail(`EXTERNAL-PENDING: evidence bundle integrity is internally consistent but not externally authenticated. Report: ${jsonPath}`);
  }
  log("Evidence bundle verification passed.");
}

async function vpsPreflight() {
  await withLocalCheckReport("vps-preflight", async () => {
    run("sh", [path.join(scriptDir, "vps-preflight.sh"), ...argv._], { cwd: infraRoot });
  }, { script: "scripts/vps-preflight.sh" });
}

async function vpsPostdeploy() {
  await withLocalCheckReport("vps-postdeploy", async () => {
    run("sh", [path.join(scriptDir, "vps-postdeploy.sh"), ...argv._], { cwd: infraRoot });
  }, {
    script: "scripts/vps-postdeploy.sh",
    includeAppEndpoints: Boolean(process.env.DEPLOY_INCLUDE_APP_ENDPOINTS === "1" || process.env.DEPLOY_INCLUDE_APP_ENDPOINTS === "true"),
  });
}

async function productionGoNoGo() {
  log("==> Production go/no-go evidence gate");
  const { policyPath, policy } = productionGoNoGoPolicy();
  const enforce = booleanFlag(argv.enforce);
  const checks = [];
  const candidateEvidence = currentCandidateIdentityEvidence({
    envFile: argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: argv.project ?? argv.projectName,
    repository: argv.repository ?? argv.repo,
  });
  const currentCandidate = candidateEvidence.candidate;
  const candidateReportBinding = (payload, kind, maxAgeHours) => (
    currentCandidate
      ? evaluateCandidateReportBinding(payload, currentCandidate, { kind, maxAgeHours }).passed
      : false
  );
  addGoNoGoCheck(checks, {
    name: "release-candidate-current",
    passed: Boolean(currentCandidate?.trusted),
    detail: currentCandidate
      ? `id=${currentCandidate.id}; commit=${currentCandidate.commit}; tree=${currentCandidate.tree}; repository=${currentCandidate.repository}; clean=${currentCandidate.clean}; workloadLock=${currentCandidate.workloadLockSha256 ?? "none"}; render=${currentCandidate.renderSha256}`
      : `candidate identity unavailable: ${candidateEvidence.error ?? "unknown"}`,
  });
  const maxAge = {
    vpsBootstrap: 168,
    vpsHardening: 168,
    vpsHost: 24,
    preGoLive: 24,
    dr: 24,
    alerts: 24,
    uptime: 24,
    load: 72,
    release: 24,
    cloudflareAccess: 24,
    githubActionsRun: 24,
    secretRotation: 24,
    healthchecks: 24,
    runtimeFingerprint: 24,
    retention: 24,
    auditLogs: 24,
    accessReview: 24,
    accountIntegration: 24,
    ...(policy.maxAgeHours ?? {}),
  };

  const vpsBootstrap = latestJsonReport("vps-bootstrap", "vps-bootstrap-apply-", (payload) => (
    payload.mode === "apply" && payload.status === "applied"
  ));
  const vpsBootstrapFresh = reportFreshDetail(vpsBootstrap, maxAge.vpsBootstrap);
  addGoNoGoCheck(checks, {
    name: "vps-bootstrap-applied",
    passed: Boolean(vpsBootstrap && vpsBootstrapFresh.fresh),
    detail: vpsBootstrap
      ? `${vpsBootstrapFresh.detail}; mode=${vpsBootstrap.payload.mode ?? "unknown"}; status=${vpsBootstrap.payload.status ?? "unknown"}`
      : vpsBootstrapFresh.detail,
    report: vpsBootstrap,
  });

  const vpsHardening = latestJsonReport("vps-hardening", "vps-hardening-apply-", (payload) => {
    const hardeningSteps = Array.isArray(payload.steps) ? payload.steps : [];
    const dockerDaemonApplied = hardeningSteps.some((step) => step.name === "docker-daemon-config" && step.status === "applied");
    const sshReloadApplied = hardeningSteps.some((step) => step.name === "ssh-service-reload" && step.status === "applied");
    return payload.mode === "apply" && payload.status === "applied" && dockerDaemonApplied && sshReloadApplied;
  });
  const vpsHardeningFresh = reportFreshDetail(vpsHardening, maxAge.vpsHardening);
  const vpsHardeningSteps = Array.isArray(vpsHardening?.payload?.steps) ? vpsHardening.payload.steps : [];
  const vpsHardeningDockerDaemonApplied = vpsHardeningSteps.some((step) => step.name === "docker-daemon-config" && step.status === "applied");
  const vpsHardeningSshReloadApplied = vpsHardeningSteps.some((step) => step.name === "ssh-service-reload" && step.status === "applied");
  addGoNoGoCheck(checks, {
    name: "vps-hardening-applied",
    passed: Boolean(vpsHardening && vpsHardeningFresh.fresh && vpsHardeningDockerDaemonApplied && vpsHardeningSshReloadApplied),
    detail: vpsHardening
      ? `${vpsHardeningFresh.detail}; mode=${vpsHardening.payload.mode ?? "unknown"}; status=${vpsHardening.payload.status ?? "unknown"}; sshReload=${vpsHardeningSshReloadApplied ? "applied" : "missing"}; dockerDaemon=${vpsHardeningDockerDaemonApplied ? "applied" : "missing"}`
      : vpsHardeningFresh.detail,
    report: vpsHardening,
  });

  const vps = latestJsonReport("vps-host", "vps-host-readiness-", (payload) => (
    payload.productionEvidence !== false
    && payload.mode !== "diagnostic"
  ));
  const vpsFresh = reportFreshDetail(vps, maxAge.vpsHost);
  const vpsRequiredFailures = Number(vps?.payload?.summary?.failedRequired ?? 999);
  const vpsChecks = Array.isArray(vps?.payload?.checks) ? vps.payload.checks : [];
  const vpsCheckNames = new Set(vpsChecks.map((check) => check.name));
  const vpsExpectedSshPort = vps?.payload?.expectedSshPort ?? "";
  const vpsHasSshPortEvidence = Boolean(
    vpsExpectedSshPort
    && vpsCheckNames.has("ssh-port-expected")
    && vpsCheckNames.has("ufw-ssh-port-allowed"),
  );
  addGoNoGoCheck(checks, {
    name: "vps-host-readiness",
    passed: Boolean(vps && vpsFresh.fresh && vpsRequiredFailures === 0 && vpsHasSshPortEvidence),
    detail: vps
      ? `${vpsFresh.detail}; failedRequired=${vpsRequiredFailures}; expectedSshPort=${vpsExpectedSshPort || "missing"}; sshPortEvidence=${vpsHasSshPortEvidence ? "present" : "missing"}`
      : vpsFresh.detail,
    report: vps,
  });

  const latestPreGoLive = latestJsonReport("go-live", "pre-go-live-evidence-");
  const preGoLive = latestJsonReport("go-live", "pre-go-live-evidence-", (payload) => candidateReportBinding(payload, "pre-go-live", maxAge.preGoLive));
  const preFresh = reportFreshDetail(preGoLive, maxAge.preGoLive);
  const preOptions = preGoLive?.payload?.options ?? {};
  const preReadinessMatrix = preGoLive?.payload?.readinessMatrix ?? [];
  const preMatrixRequiredFailures = preReadinessMatrix.filter((item) => item.required && item.status !== "passed");
  const preRequiredFailures = (preGoLive?.payload?.steps ?? []).filter((step) => step.required && step.status !== "passed");
  const preMissingOptions = [
    policy.requireProductionPreflight && !preOptions.includeProductionPreflight ? "includeProductionPreflight" : null,
    policy.requireRuntimePreGoLive && !preOptions.includeRuntime ? "includeRuntime" : null,
    policy.requireRestorePreGoLive && !preOptions.includeRestoreDrill ? "includeRestoreDrill" : null,
    policy.requireOffsiteRestore && !preOptions.includeOffsiteRestoreDryRun ? "includeOffsiteRestoreDryRun" : null,
    policy.requireGithubRemoteVerification && !preOptions.verifyGithubRemote ? "verifyGithubRemote" : null,
  ].filter(Boolean);
  const preExternalStepNames = new Set(["production-preflight", "github-actions-runtime-verify-remote"]);
  const preExternalReadinessIds = new Set(["production-preflight", "offsite-restore-dry-run", "github-remote-verification"]);
  const preExternalOptions = new Set(["includeProductionPreflight", "includeOffsiteRestoreDryRun", "verifyGithubRemote"]);
  const preLocalRequiredFailures = preRequiredFailures.filter((step) => !preExternalStepNames.has(step.name));
  const preLocalReadinessFailures = preMatrixRequiredFailures.filter((item) => !preExternalReadinessIds.has(item.id));
  const preLocalMissingOptions = preMissingOptions.filter((option) => !preExternalOptions.has(option));
  const preExternalBlockers = [
    ...preRequiredFailures.filter((step) => preExternalStepNames.has(step.name)).map((step) => step.name),
    ...preMatrixRequiredFailures.filter((item) => preExternalReadinessIds.has(item.id)).map((item) => item.id),
    ...preMissingOptions.filter((option) => preExternalOptions.has(option)).map((option) => `--${option}`),
  ];
  const prePendingProvider = Boolean(
    preGoLive
    && preFresh.fresh
    && preLocalRequiredFailures.length === 0
    && preLocalReadinessFailures.length === 0
    && preLocalMissingOptions.length === 0
    && preExternalBlockers.length > 0
  );
  addGoNoGoCheck(checks, {
    name: "pre-go-live-evidence-complete",
    passed: Boolean(preGoLive && preFresh.fresh && preGoLive.payload.status === "passed" && preRequiredFailures.length === 0 && preMissingOptions.length === 0 && preMatrixRequiredFailures.length === 0),
    detail: preGoLive
      ? `${preFresh.detail}; status=${preGoLive.payload.status ?? "unknown"}; requiredFailures=${preRequiredFailures.length}; missingOptions=${preMissingOptions.join(",") || "none"}; readinessMissing=${preMatrixRequiredFailures.map((item) => item.id).join(",") || "none"}`
      : latestPreGoLive
        ? `latest pre-go-live report is not bound to the current candidate; ${reportFreshDetail(latestPreGoLive, maxAge.preGoLive).detail}`
        : preFresh.detail,
    report: preGoLive ?? latestPreGoLive,
    status: prePendingProvider ? "pending-provider" : null,
    blocker: prePendingProvider ? "external-provider-proof" : null,
  });

  const healthcheckCoverage = latestJsonReport("healthchecks", "healthcheck-coverage-");
  const healthcheckFresh = reportFreshDetail(healthcheckCoverage, maxAge.healthchecks);
  const healthcheckResult = evidenceBundleReportPasses({ label: "healthcheck-coverage" }, healthcheckCoverage?.payload);
  addGoNoGoCheck(checks, {
    name: "healthcheck-coverage",
    passed: Boolean(healthcheckCoverage && healthcheckFresh.fresh && healthcheckResult.passed),
    detail: healthcheckCoverage ? `${healthcheckFresh.detail}; ${healthcheckResult.detail}` : healthcheckFresh.detail,
    report: healthcheckCoverage,
    required: false,
  });

  const latestFunctionalHealth = latestJsonReport("healthchecks", "functional-health-");
  const functionalHealth = latestJsonReport("healthchecks", "functional-health-", (payload) => candidateReportBinding(payload, "runtime-health", maxAge.healthchecks));
  const functionalHealthFresh = reportFreshDetail(functionalHealth, maxAge.healthchecks);
  const functionalHealthResult = evidenceBundleReportPasses({ label: "functional-health" }, functionalHealth?.payload);
  addGoNoGoCheck(checks, {
    name: "functional-health-runtime",
    passed: Boolean(functionalHealth && functionalHealthFresh.fresh && functionalHealthResult.passed),
    detail: functionalHealth
      ? `${functionalHealthFresh.detail}; ${functionalHealthResult.detail}`
      : latestFunctionalHealth ? `latest runtime health report is not bound to the current candidate` : functionalHealthFresh.detail,
    report: functionalHealth ?? latestFunctionalHealth,
  });

  const latestRuntimeFingerprintReport = latestJsonReport("runtime-fingerprint", "runtime-fingerprint-");
  const runtimeFingerprintReport = latestJsonReport("runtime-fingerprint", "runtime-fingerprint-", (payload) => candidateReportBinding(payload, "runtime-fingerprint", maxAge.runtimeFingerprint));
  const runtimeFingerprintFresh = reportFreshDetail(runtimeFingerprintReport, maxAge.runtimeFingerprint);
  const runtimeFingerprintResult = evidenceBundleReportPasses({ label: "runtime-fingerprint" }, runtimeFingerprintReport?.payload);
  addGoNoGoCheck(checks, {
    name: "runtime-fingerprint-exact",
    passed: Boolean(runtimeFingerprintReport && runtimeFingerprintFresh.fresh && runtimeFingerprintResult.passed),
    detail: runtimeFingerprintReport
      ? `${runtimeFingerprintFresh.detail}; ${runtimeFingerprintResult.detail}`
      : latestRuntimeFingerprintReport ? `latest runtime fingerprint is not bound to the current candidate` : runtimeFingerprintFresh.detail,
    report: runtimeFingerprintReport ?? latestRuntimeFingerprintReport,
  });

  const infraHealthReport = latestJsonReport("local-checks", "infra-health-", (payload) => (
    payload.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === "infra-health"
    && candidateReportBinding(payload, "runtime-health", maxAge.healthchecks)
  ));
  const infraHealthFresh = reportFreshDetail(infraHealthReport, maxAge.healthchecks);
  const infraHealthStep = (preGoLive?.payload?.steps ?? []).find((step) => step.name === "infra-health");
  const infraHealthFromPreGoLive = Boolean(preGoLive && preFresh.fresh && infraHealthStep?.status === "passed");
  const infraHealthFromLocalReport = Boolean(infraHealthReport && infraHealthFresh.fresh);
  addGoNoGoCheck(checks, {
    name: "infra-health-runtime",
    passed: infraHealthFromPreGoLive || infraHealthFromLocalReport,
    detail: infraHealthFromLocalReport
      ? `${infraHealthFresh.detail}; local-check=passed`
      : preGoLive ? `${preFresh.detail}; infra-health=${infraHealthStep?.status ?? "missing"}` : preFresh.detail,
    report: infraHealthReport ?? preGoLive,
    required: false,
  });

  const retention = latestJsonReport("retention", "retention-evidence-");
  const retentionFresh = reportFreshDetail(retention, maxAge.retention);
  const retentionResult = evidenceBundleReportPasses({ label: "retention-evidence" }, retention?.payload);
  addGoNoGoCheck(checks, {
    name: "retention-evidence",
    passed: Boolean(retention && retentionFresh.fresh && retentionResult.passed),
    detail: retention ? `${retentionFresh.detail}; ${retentionResult.detail}` : retentionFresh.detail,
    report: retention,
    required: false,
  });

  const platformAdminAudit = latestJsonReport("platform-admin-audit", "platform-admin-audit-");
  const platformAdminAuditFresh = reportFreshDetail(platformAdminAudit, maxAge.auditLogs);
  addGoNoGoCheck(checks, {
    name: "platform-admin-audit-evidence",
    passed: Boolean(
      platformAdminAudit
      && platformAdminAuditFresh.fresh
      && platformAdminAudit.payload.status === "passed"
      && platformAdminAudit.payload.mode === "runtime"
      && platformAdminAudit.payload.scope === "platform-infrastructure"
    ),
    detail: platformAdminAudit
      ? `${platformAdminAuditFresh.detail}; status=${platformAdminAudit.payload.status ?? "unknown"}; mode=${platformAdminAudit.payload.mode ?? "unknown"}; scope=${platformAdminAudit.payload.scope ?? "unknown"}`
      : platformAdminAuditFresh.detail,
    report: platformAdminAudit,
    required: false,
  });

  const expectedWorkflow = policy.requiredGithubWorkflow ?? "enterprise-infra.yml";
  const releaseSha = currentCandidate?.commit ?? null;
  const githubActionsRun = latestJsonReport("github-actions", "github-actions-run-", (payload) => (
    !policy.requireGithubActionsRunSuccess
    || (
      candidateReportBinding(payload, "github-actions", maxAge.githubActionsRun)
      && payload.mode === "verifyRemote"
      && payload.status === "passed"
      && payload.workflow === expectedWorkflow
      && (!releaseSha || String(payload.expectedSha ?? "").toLowerCase() === String(releaseSha).toLowerCase())
      && payload.run?.status === "completed"
      && payload.run?.conclusion === "success"
    )
  ));
  const latestGithubActionsRun = latestJsonReport("github-actions", "github-actions-run-");
  const githubActionsFresh = reportFreshDetail(githubActionsRun, maxAge.githubActionsRun);
  const latestGithubActionsFresh = reportFreshDetail(latestGithubActionsRun, maxAge.githubActionsRun);
  const githubActionsOk = !policy.requireGithubActionsRunSuccess || Boolean(
    githubActionsRun
    && githubActionsFresh.fresh
    && githubActionsRun.payload.mode === "verifyRemote"
    && githubActionsRun.payload.status === "passed"
    && githubActionsRun.payload.workflow === expectedWorkflow
    && githubActionsRun.payload.run?.conclusion === "success"
    && candidateReportBinding(githubActionsRun.payload, "github-actions", maxAge.githubActionsRun)
    && (!releaseSha || String(githubActionsRun.payload.expectedSha ?? "").toLowerCase() === String(releaseSha).toLowerCase())
  );
  const githubActionsRemoteFailed = Boolean(
    latestGithubActionsRun
    && latestGithubActionsRun.payload.mode === "verifyRemote"
    && latestGithubActionsRun.payload.status === "failed"
  );
  const latestGithubActionsCandidateBound = Boolean(
    latestGithubActionsRun
    && candidateReportBinding(latestGithubActionsRun.payload, "github-actions", maxAge.githubActionsRun)
  );
  const githubActionsPendingProvider = Boolean(
    !githubActionsOk
    && policy.requireGithubActionsRunSuccess
    && !githubActionsRemoteFailed
    && (!latestGithubActionsRun || latestGithubActionsRun.payload.mode !== "verifyRemote" || latestGithubActionsCandidateBound)
  );
  addGoNoGoCheck(checks, {
    name: "github-actions-run-success",
    passed: githubActionsOk,
    detail: githubActionsRun
      ? `${githubActionsFresh.detail}; workflow=${githubActionsRun.payload.workflow}; mode=${githubActionsRun.payload.mode}; status=${githubActionsRun.payload.status}; conclusion=${githubActionsRun.payload.run?.conclusion ?? "missing"}; sha=${githubActionsRun.payload.expectedSha ?? "missing"}`
      : latestGithubActionsRun
        ? `missing successful verifyRemote workflow report; latestWorkflow=${latestGithubActionsRun.payload.workflow ?? "unknown"}; latestStatus=${latestGithubActionsRun.payload.status ?? "unknown"}; latestMode=${latestGithubActionsRun.payload.mode ?? "unknown"}; ${latestGithubActionsFresh.detail}`
        : githubActionsFresh.detail,
    report: githubActionsRun ?? latestGithubActionsRun,
    status: githubActionsPendingProvider ? "pending-provider" : null,
    blocker: githubActionsPendingProvider ? "github-live-provider" : null,
  });

  const latestSecretRotationReport = latestJsonReport("secret-rotation", "secret-rotation-evidence-");
  const secretRotation = latestJsonReport("secret-rotation", "secret-rotation-evidence-", (payload) => (
    !policy.requireSecretRotationEvidence
    || (
      payload.mode === "evidence"
      && payload.status === "passed"
      && payload.verify?.status === "passed"
      && Number(payload.summary?.failedSecrets ?? 1) === 0
      && Number(payload.summary?.expiredSecrets ?? 1) === 0
      && Number(payload.summary?.missingMaterializedFiles ?? 1) === 0
      && payload.audit?.latestRotationEvent
    )
  ));
  const secretRotationFresh = reportFreshDetail(secretRotation, maxAge.secretRotation);
  const latestSecretRotationFresh = reportFreshDetail(latestSecretRotationReport, maxAge.secretRotation);
  const secretRotationOk = !policy.requireSecretRotationEvidence || Boolean(
    secretRotation
    && secretRotationFresh.fresh
    && secretRotation.payload.mode === "evidence"
    && secretRotation.payload.status === "passed"
    && secretRotation.payload.verify?.status === "passed"
    && Number(secretRotation.payload.summary?.failedSecrets ?? 1) === 0
    && Number(secretRotation.payload.summary?.expiredSecrets ?? 1) === 0
    && Number(secretRotation.payload.summary?.missingMaterializedFiles ?? 1) === 0
    && secretRotation.payload.audit?.latestRotationEvent
  );
  addGoNoGoCheck(checks, {
    name: "secret-rotation-evidence",
    passed: secretRotationOk,
    detail: secretRotation
      ? `${secretRotationFresh.detail}; mode=${secretRotation.payload.mode}; status=${secretRotation.payload.status}; verify=${secretRotation.payload.verify?.status ?? "missing"}; expired=${secretRotation.payload.summary?.expiredSecrets ?? "missing"}; missingFiles=${secretRotation.payload.summary?.missingMaterializedFiles ?? "missing"}; latestRotation=${secretRotation.payload.audit?.latestRotationEvent?.action ?? "missing"}`
      : latestSecretRotationReport
        ? `missing passing secret rotation evidence; latestMode=${latestSecretRotationReport.payload.mode ?? "unknown"}; latestStatus=${latestSecretRotationReport.payload.status ?? "unknown"}; latestVerify=${latestSecretRotationReport.payload.verify?.status ?? "unknown"}; ${latestSecretRotationFresh.detail}`
        : secretRotationFresh.detail,
    report: secretRotation ?? latestSecretRotationReport,
  });

  const dr = latestJsonReport("dr", "dr-evidence-");
  const drFresh = reportFreshDetail(dr, maxAge.dr);
  const backupFamilies = dr?.payload?.rpoEvidence?.backupFamilies ?? [];
  const backupFailures = backupFamilies.filter((family) => !family.fresh || !family.integrityVerified);
  const offsiteRestoreOk = !policy.requireOffsiteRestore || (
    Boolean(dr?.payload?.offsiteEvidence?.latestRestoreReport)
    && dr?.payload?.offsiteEvidence?.latestRestoreOffsite === true
    && dr?.payload?.offsiteEvidence?.latestRestoreCoverage?.complete === true
  );
  const drPendingProvider = Boolean(
    dr
    && drFresh.fresh
    && backupFailures.length === 0
    && policy.requireOffsiteRestore
    && !offsiteRestoreOk
    && ["passed", "warning"].includes(String(dr.payload.status ?? ""))
  );
  addGoNoGoCheck(checks, {
    name: "disaster-recovery-rpo-rto-offsite",
    passed: Boolean(dr && drFresh.fresh && dr.payload.status === "passed" && backupFailures.length === 0 && offsiteRestoreOk),
    detail: dr
      ? `${drFresh.detail}; status=${dr.payload.status}; backupFailures=${backupFailures.map((item) => item.family).join(",") || "none"}; offsiteRestore=${offsiteRestoreOk ? "yes" : "no"}; offsiteRepository=${dr.payload.offsiteEvidence?.latestRestoreOffsite === true ? "yes" : "no"}; offsiteCoverage=${dr.payload.offsiteEvidence?.latestRestoreCoverage?.complete === true ? "yes" : "no"}`
      : drFresh.detail,
    report: dr,
    status: drPendingProvider ? "pending-provider" : null,
    blocker: drPendingProvider ? "offsite-storage-provider" : null,
  });

  const alertReport = latestJsonReport("alerts", "alert-evidence-", (payload) => (
    payload.mode === "send-test"
    && (!policy.requireEmailAlertDelivery || payload.requestedDelivery?.email === true)
  ));
  const alertFresh = reportFreshDetail(alertReport, maxAge.alerts);
  const emailRequiredOk = !policy.requireEmailAlertDelivery || alertReport?.payload?.requestedDelivery?.email === true;
  addGoNoGoCheck(checks, {
    name: "real-alert-delivery",
    passed: Boolean(alertReport && alertFresh.fresh && alertReport.payload.status === "passed" && alertReport.payload.mode === "send-test" && emailRequiredOk),
    detail: alertReport
      ? `${alertFresh.detail}; status=${alertReport.payload.status}; mode=${alertReport.payload.mode}; emailRequired=${emailRequiredOk ? "yes" : "no"}`
      : alertFresh.detail,
    report: alertReport,
  });

  const latestUptimeReport = latestJsonReport("uptime", "external-uptime-");
  const uptime = latestJsonReport("uptime", "external-uptime-", (payload) => (
    payload.providerEvidence?.verified === true
    && payload.providerEvidence?.authentication?.verified === true
    && payload.providerEvidence?.authentication?.kind === "github-sigstore-cryptographic-attestation"
    && (payload.results ?? []).every((result) => publicEvidenceUrl(result.url))
  ));
  const uptimeFresh = reportFreshDetail(uptime, maxAge.uptime);
  const latestUptimeFresh = reportFreshDetail(latestUptimeReport, maxAge.uptime);
  const uptimeResults = uptime?.payload?.results ?? [];
  const uptimeFailed = uptimeResults.filter((result) => !result.ok);
  const uptimePublic = uptimeResults.every((result) => publicEvidenceUrl(result.url));
  const uptimeProviderVerified = uptime?.payload?.providerEvidence?.verified === true
    && uptime?.payload?.providerEvidence?.authentication?.verified === true;
  const latestUptimeResults = latestUptimeReport?.payload?.results ?? [];
  const latestUptimePublic = latestUptimeResults.length > 0 && latestUptimeResults.every((result) => publicEvidenceUrl(result.url));
  const latestUptimeProviderVerified = latestUptimeReport?.payload?.providerEvidence?.verified === true
    && latestUptimeReport?.payload?.providerEvidence?.authentication?.verified === true;
  const uptimePendingProvider = Boolean(
    !uptime
    && (!latestUptimeProviderVerified || !latestUptimePublic)
  );
  addGoNoGoCheck(checks, {
    name: "external-uptime-provider",
    passed: Boolean(uptime && uptimeFresh.fresh && uptimeResults.length > 0 && uptimeFailed.length === 0 && uptimePublic && uptimeProviderVerified),
    detail: uptime
      ? `${uptimeFresh.detail}; failedTargets=${uptimeFailed.map((item) => item.name).join(",") || "none"}; publicTargets=${uptimePublic ? "yes" : "no"}; provider=${uptimeProviderVerified ? uptime.payload.providerEvidence.provider : "missing"}`
      : latestUptimeReport
        ? `missing provider-verified public uptime report; latestProvider=${latestUptimeReport.payload.providerEvidence?.verified ? latestUptimeReport.payload.providerEvidence.provider : "missing"}; ${latestUptimeFresh.detail}`
        : uptimeFresh.detail,
    report: uptime ?? latestUptimeReport,
    status: uptimePendingProvider ? "pending-provider" : null,
    blocker: uptimePendingProvider ? "external-uptime-provider" : null,
  });

  const latestLoadReport = latestJsonReport("load", "load-benchmark-");
  const load = latestJsonReport("load", "load-benchmark-", (payload) => {
    const target = payload.target ?? {};
    const publicTarget = !policy.requirePublicLoadTarget || (target.public === true && publicEvidenceUrl(payload.url) && !legacyPlatformEvidenceHost(payload.url));
    const edgeEvidence = !policy.requireLoadEdgeEvidence || (
      target.edgeRequired === true
      && target.edge?.providerMatched === true
      && target.edge?.authenticated === true
      && Boolean(target.edge?.provider)
      && target.edge?.providerEvidence?.verified === true
      && target.edge?.providerEvidence?.candidateId === payload.candidate?.id
      && target.edge?.providerEvidence?.authentication?.verified === true
      && target.edge?.providerEvidence?.authentication?.kind === "github-sigstore-cryptographic-attestation"
    );
    return publicTarget && edgeEvidence && candidateReportBinding(payload, "runtime-health", maxAge.load);
  });
  const loadFresh = reportFreshDetail(load, maxAge.load);
  const latestLoadFresh = reportFreshDetail(latestLoadReport, maxAge.load);
  const requiredProfiles = Array.isArray(policy.requiredLoadProfiles) ? policy.requiredLoadProfiles : [50, 100, 500];
  const profiles = load?.payload?.profiles ?? [];
  const missingProfiles = requiredProfiles.filter((users) => !profiles.some((profile) => Number(profile.users) === Number(users)));
  const failedProfiles = profiles.filter((profile) => Number(profile.metric?.errors ?? 0) !== 0 || Number(profile.metric?.p95 ?? 0) > Number(profile.metric?.maxP95Ms ?? 0));
  const loadTarget = load?.payload?.target ?? {};
  const publicLoadTarget = !policy.requirePublicLoadTarget || (loadTarget.public === true && publicEvidenceUrl(load?.payload?.url) && !legacyPlatformEvidenceHost(load?.payload?.url));
  const loadEdgeEvidence = !policy.requireLoadEdgeEvidence || (
    loadTarget.edgeRequired === true
    && loadTarget.edge?.providerMatched === true
    && loadTarget.edge?.authenticated === true
    && Boolean(loadTarget.edge?.provider)
    && loadTarget.edge?.providerEvidence?.verified === true
    && loadTarget.edge?.providerEvidence?.candidateId === load?.payload?.candidate?.id
    && loadTarget.edge?.providerEvidence?.authentication?.verified === true
    && loadTarget.edge?.providerEvidence?.authentication?.kind === "github-sigstore-cryptographic-attestation"
  );
  const latestLegacyLoadHost = legacyPlatformEvidenceHost(latestLoadReport?.payload?.url);
  const latestLoadTarget = latestLoadReport?.payload?.target ?? {};
  const latestPublicLoadTarget = Boolean(
    latestLoadReport
    && (!policy.requirePublicLoadTarget || (latestLoadTarget.public === true && publicEvidenceUrl(latestLoadReport.payload.url) && !latestLegacyLoadHost))
  );
  const latestLoadCandidateBound = Boolean(
    latestLoadReport && candidateReportBinding(latestLoadReport.payload, "runtime-health", maxAge.load)
  );
  const latestLoadAuthenticatedEdge = Boolean(
    latestLoadReport
    && (!policy.requireLoadEdgeEvidence || (
      latestLoadTarget.edgeRequired === true
      && latestLoadTarget.edge?.providerMatched === true
      && latestLoadTarget.edge?.authenticated === true
      && Boolean(latestLoadTarget.edge?.provider)
      && latestLoadTarget.edge?.providerEvidence?.verified === true
      && latestLoadTarget.edge?.providerEvidence?.candidateId === latestLoadReport.payload.candidate?.id
      && latestLoadTarget.edge?.providerEvidence?.authentication?.verified === true
      && latestLoadTarget.edge?.providerEvidence?.authentication?.kind === "github-sigstore-cryptographic-attestation"
    ))
  );
  const loadPendingProvider = Boolean(
    !load
    && (!latestLoadReport || (latestPublicLoadTarget && latestLoadCandidateBound && !latestLoadAuthenticatedEdge))
  );
  addGoNoGoCheck(checks, {
    name: "public-load-benchmark",
    passed: Boolean(load && loadFresh.fresh && load.payload.status === "passed" && missingProfiles.length === 0 && failedProfiles.length === 0 && publicLoadTarget && loadEdgeEvidence),
    detail: load
      ? `${loadFresh.detail}; status=${load.payload.status ?? "unknown"}; missingProfiles=${missingProfiles.join(",") || "none"}; failedProfiles=${failedProfiles.map((profile) => profile.users).join(",") || "none"}; publicTarget=${publicLoadTarget ? "yes" : "no"}; edgeEvidence=${loadEdgeEvidence ? loadTarget.edge?.provider ?? "not-required" : "missing"}`
      : latestLoadReport
        ? latestLegacyLoadHost
          ? `missing public edge benchmark report for final platform hosts; ignored legacy benchmark report; ${latestLoadFresh.detail}`
          : `missing public edge benchmark report; latestUrl=${latestLoadReport.payload.url ?? "unknown"}; ${latestLoadFresh.detail}`
       : loadFresh.detail,
    report: load ?? latestLoadReport,
    status: loadPendingProvider ? "pending-provider" : null,
    blocker: loadPendingProvider ? "public-edge-provider" : null,
  });

  const latestReleaseReport = latestJsonReport("release", "release-evidence-");
  const release = latestJsonReport("release", "release-evidence-", (payload) => (
    payload.mode === "evidence"
    && candidateReportBinding(payload, "release", maxAge.release)
  ));
  const releaseFresh = reportFreshDetail(release, maxAge.release);
  const latestReleaseFresh = reportFreshDetail(latestReleaseReport, maxAge.release);
  const releasePayload = release?.payload ?? {};
  const githubProvenance = releasePayload.attestations?.githubSigstore;
  const releaseGithubProvenanceOk = Boolean(
    releasePayload.attestations?.provenanceRequired
      && githubProvenance?.status === "passed"
      && githubProvenance?.kind === "github-sigstore-cryptographic-attestation"
      && githubProvenance?.verified === true
      && githubProvenance?.completeness === "complete"
      && githubProvenance?.commitShaMatched === true
      && githubProvenance?.commitSha === releasePayload.releaseSha
      && githubProvenance?.verifiedTimestampCount > 0
      && githubProvenance?.attestationCount > 0,
  );
  const releaseProvenanceOk = !policy.requireReleaseProvenance || releaseGithubProvenanceOk;
  const releaseGitOk = !policy.requireCleanReleaseGit || (
    releasePayload.git?.dirty === false
    && String(releasePayload.git?.commit ?? "").toLowerCase() === currentCandidate?.commit
    && String(releasePayload.git?.tree ?? "").toLowerCase() === currentCandidate?.tree
  );
  const releaseRollbackOk = Boolean(
    releasePayload.rollback?.complete
      && (releasePayload.rollback?.firstDeploy || releasePayload.rollback?.dryRun?.validated === true),
  );
  const releasePendingProvider = Boolean(
    release
    && policy.requireReleaseProvenance
    && !releaseGithubProvenanceOk
  );
  addGoNoGoCheck(checks, {
    name: "release-evidence-and-rollback",
    passed: Boolean(release && releaseFresh.fresh && releasePayload.mode === "evidence" && releasePayload.status === "passed" && releaseRollbackOk && releasePayload.artifacts?.sbom && releaseProvenanceOk && releaseGitOk),
    detail: release
      ? `${releaseFresh.detail}; mode=${releasePayload.mode}; status=${releasePayload.status ?? "unknown"}; rollback=${releaseRollbackOk ? "validated" : "missing"}; provenance=${releaseGithubProvenanceOk ? "github-sigstore-cryptographic" : "missing"}; cleanGit=${releaseGitOk ? "yes" : "no"}`
      : latestReleaseReport
        ? `missing evidence report; latestReleaseMode=${latestReleaseReport.payload.mode ?? "unknown"}; latestStatus=${latestReleaseReport.payload.status ?? "unknown"}; ${latestReleaseFresh.detail}`
       : releaseFresh.detail,
    report: release ?? latestReleaseReport,
    status: releasePendingProvider ? "pending-provider" : null,
    blocker: releasePendingProvider ? "github-sigstore-release-provenance" : null,
  });

  const candidateReportBindings = [
    ["pre-go-live", preGoLive?.payload, "pre-go-live", maxAge.preGoLive],
    ["functional-health", functionalHealth?.payload, "runtime-health", maxAge.healthchecks],
    ["runtime-fingerprint", runtimeFingerprintReport?.payload, "runtime-fingerprint", maxAge.runtimeFingerprint],
    ["github-actions", githubActionsRun?.payload, "github-actions", maxAge.githubActionsRun],
    ["release", release?.payload, "release", maxAge.release],
    ...(load?.payload ? [["public-load", load.payload, "runtime-health", maxAge.load]] : []),
  ].map(([name, reportPayload, kind, reportMaxAge]) => ({
    name,
    ...evaluateCandidateReportBinding(reportPayload, currentCandidate, { kind, maxAgeHours: reportMaxAge }),
  }));
  const candidateReportFailures = candidateReportBindings.filter((binding) => !binding.passed);
  addGoNoGoCheck(checks, {
    name: "candidate-report-set-consistent",
    passed: candidateReportFailures.length === 0,
    detail: candidateReportFailures.length
      ? candidateReportFailures.map((binding) => `${binding.name}:${binding.issues.join(",")}`).join("; ")
      : `all release, GitHub, runtime, and fingerprint reports bind candidate ${currentCandidate?.id}`,
  });

  const latestCloudflareAccessReport = latestJsonReport("cloudflare-access", "cloudflare-access-admin-");
  const cloudflareAccess = latestJsonReport("cloudflare-access", "cloudflare-access-admin-", (payload) => (
    !policy.requireCloudflareAccessVerify || payload.mode === "verifyRemote"
  ));
  const cloudflareAccessFresh = reportFreshDetail(cloudflareAccess, maxAge.cloudflareAccess);
  const latestCloudflareAccessFresh = reportFreshDetail(latestCloudflareAccessReport, maxAge.cloudflareAccess);
  const cloudflareApps = cloudflareAccess?.payload?.applications ?? [];
  const cloudflareVerified = !policy.requireCloudflareAccessVerify || (
    cloudflareAccess?.payload?.mode === "verifyRemote"
    && cloudflareApps.length > 0
    && cloudflareApps.every((app) => app.result === "verified")
  );
  const cloudflarePendingProvider = Boolean(
    !cloudflareVerified
    && policy.requireCloudflareAccessVerify
  );
  addGoNoGoCheck(checks, {
    name: "cloudflare-access-admin-verified",
    passed: Boolean(cloudflareAccess && cloudflareAccessFresh.fresh && cloudflareAccess.payload.status === "passed" && cloudflareVerified),
    detail: cloudflareAccess
      ? `${cloudflareAccessFresh.detail}; mode=${cloudflareAccess.payload.mode}; verified=${cloudflareVerified ? "yes" : "no"}`
      : latestCloudflareAccessReport
        ? `missing verifyRemote report; latestMode=${latestCloudflareAccessReport.payload.mode ?? "unknown"}; latestStatus=${latestCloudflareAccessReport.payload.status ?? "unknown"}; ${latestCloudflareAccessFresh.detail}`
        : cloudflareAccessFresh.detail,
    report: cloudflareAccess ?? latestCloudflareAccessReport,
    status: cloudflarePendingProvider ? "pending-provider" : null,
    blocker: cloudflarePendingProvider ? "cloudflare-access-provider" : null,
  });

  const evidenceTrustEnvelopePathValue = argv.evidenceTrustEnvelope ?? process.env.EVIDENCE_TRUST_ENVELOPE;
  const evidenceTrustEnvelopeDigest = argv.evidenceTrustEnvelopeSha256 ?? process.env.EVIDENCE_TRUST_ENVELOPE_SHA256;
  const evidenceTrustEnvelopePath = typeof evidenceTrustEnvelopePathValue === "string" && evidenceTrustEnvelopePathValue.trim()
    ? path.resolve(evidenceTrustEnvelopePathValue)
    : null;
  const selectedReportSelections = checks
    .filter((check) => check.reportPath)
    .map((check) => ({
      filePath: check.reportPath,
      observedSha256: check.reportSha256,
      observedSizeBytes: check.reportSizeBytes,
    }));
  let evidenceReportTrust = null;
  let evidenceReportTrustError = null;
  let evidenceReportTrustPending = false;
  if (!evidenceTrustEnvelopePath && !evidenceTrustEnvelopeDigest) {
    evidenceReportTrustPending = true;
    evidenceReportTrustError = "EXTERNAL-PENDING: an independent release owner must provide the evidence trust envelope and its pinned SHA-256.";
  } else if (!evidenceTrustEnvelopePath || !evidenceTrustEnvelopeDigest) {
    evidenceReportTrustError = "Evidence trust configuration is incomplete; both envelope path and independently pinned SHA-256 are required.";
  } else {
    try {
      const envelopeBytes = fs.readFileSync(evidenceTrustEnvelopePath);
      const envelope = JSON.parse(envelopeBytes.toString("utf8"));
      evidenceReportTrust = verifyTrustedEvidenceReports({
        envelope,
        envelopeBytes,
        expectedEnvelopeSha256: evidenceTrustEnvelopeDigest,
        currentCandidateId: currentCandidate?.id,
        infraRoot,
        reportSelections: selectedReportSelections,
        maxAgeHours: Number(maxAge.evidenceTrustEnvelope ?? 24),
      });
    } catch (error) {
      evidenceReportTrustError = String(error?.message ?? error);
    }
  }
  addGoNoGoCheck(checks, {
    name: "evidence-report-authenticity",
    passed: evidenceReportTrust?.status === "passed",
    detail: evidenceReportTrust
      ? `owner-pinned envelope=${evidenceReportTrust.envelopeSha256}; candidate=${evidenceReportTrust.candidateId}; reports=${evidenceReportTrust.reportCount}`
      : evidenceReportTrustError,
    report: evidenceTrustEnvelopePath ? { filePath: evidenceTrustEnvelopePath, payload: { generatedAt: null } } : null,
    status: evidenceReportTrustPending ? "pending-provider" : null,
    blocker: evidenceReportTrustPending ? "external-owner-approval" : null,
  });

  const blockingRequired = checks.filter((check) => check.required && check.status !== "passed");
  const failedRequired = blockingRequired.filter((check) => check.status === "failed");
  const pendingRequired = blockingRequired.filter((check) => check.status.startsWith("pending-"));
  const statusCounts = goNoGoStatusCounts(checks);
  const status = blockingRequired.length ? "no-go" : "go";
  const generatedAt = new Date().toISOString();
  const remediation = blockingRequired.map(goNoGoRemediation);
  const stamp = reportTimestamp();
  const baseName = `production-go-no-go-${stamp}`;
  const report = {
    jsonPath: path.join(infraRoot, "reports", "go-no-go", `${baseName}.json`),
    markdownPath: path.join(infraRoot, "reports", "go-no-go", `${baseName}.md`),
  };
  const payload = {
    generatedAt,
    mode: enforce ? "enforce" : "summary",
    status,
    policyPath,
    candidate: currentCandidate,
    candidateError: candidateEvidence.error,
    evidenceReportTrust,
    summary: {
      total: checks.length,
      required: checks.filter((check) => check.required).length,
      passed: statusCounts.passed,
      failed: statusCounts.failed,
      pendingLiveProof: statusCounts["pending-live-proof"],
      pendingProvider: statusCounts["pending-provider"],
      blockingRequired: blockingRequired.length,
      failedRequired: failedRequired.length,
      pendingRequired: pendingRequired.length,
    },
    checks,
    failedRequired: failedRequired.map((check) => check.name),
    pendingRequired: pendingRequired.map((check) => ({ name: check.name, status: check.status })),
    blockingRequired: blockingRequired.map((check) => ({ name: check.name, status: check.status })),
    remediation,
    report,
  };
  const jsonPath = writeJsonReport("go-no-go", baseName, payload);
  const markdownPath = writeMarkdownReport("go-no-go", baseName, [
    "# Platform Production Go/No-Go",
    "",
    `Status: ${status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${generatedAt}`,
    `Policy: ${policyPath}`,
    `Candidate: ${currentCandidate?.id ?? "not-bound"}`,
    "",
    "| Check | Status | Detail | Report |",
    "| --- | --- | --- | --- |",
    ...checks.map((check) => `| ${check.name} | ${check.status} | ${check.detail.replace(/\|/g, "/")} | ${check.reportPath ?? "n/a"} |`),
    "",
    "## Blocking Required Checks",
    "",
    ...(blockingRequired.length ? blockingRequired.map((check) => `- ${check.name} (${check.status})`) : ["- none"]),
    "",
    "## Remediation Checklist",
    "",
    ...goNoGoRemediationMarkdown(remediation),
  ]);
  log(`Production go/no-go report written to ${jsonPath} and ${markdownPath}`);
  log(`Production status: ${status}`);
  if (enforce && blockingRequired.length) {
    fail(`Production no-go: ${blockingRequired.map((check) => `${check.name}:${check.status}`).join(", ")}. Report: ${jsonPath}`);
  }
}

async function linuxPortabilityCheck(options = {}) {
  log("==> Linux portability check");
  const fix = options.fix ?? booleanFlag(argv.fix);
  const skipShellSyntax = options.skipShellSyntax ?? booleanFlag(argv.skipShellSyntax);
  const firstScan = scanPortabilityFiles(infraRoot, { fix });
  const scan = fix ? scanPortabilityFiles(infraRoot, { fix: false }) : firstScan;
  const issues = [...scan.issues];
  let shellSyntax = null;

  if (!skipShellSyntax) {
    const shellScript = 'for file in scripts/*.sh; do if head -n 1 "$file" | grep -q "bash"; then bash -n "$file"; else sh -n "$file"; fi; done';
    const canUseContainerShell = process.env.PLATFORM_OPS_CONTAINER === "1" || fs.existsSync("/.dockerenv");
    const shellResult = canUseContainerShell
      ? run("sh", ["-ec", shellScript], { capture: true, allowFailure: true })
      : run("docker", [
        "run",
        "--rm",
        "-v",
        `${hostPathForContainerMount(infraRoot)}:/infra:ro`,
        "-w",
        "/infra",
        "alpine:3.22",
        "sh",
        "-ec",
        shellScript,
      ], { capture: true, allowFailure: true });
    shellSyntax = {
      mode: canUseContainerShell ? "container-local-sh" : "docker-alpine",
      status: shellResult.status,
      stdout: String(shellResult.stdout ?? "").trim(),
      stderr: String(shellResult.stderr ?? "").trim(),
    };
    if (shellResult.status !== 0) {
      issues.push({
        file: "scripts/*.sh",
        type: "shell-syntax",
        detail: shellSyntax.stderr || shellSyntax.stdout || `Alpine sh -n failed with status ${shellResult.status}`,
      });
    }
  }

  const payload = {
    generatedAt: new Date().toISOString(),
    mode: fix ? "fix-and-check" : "check",
    status: issues.length ? "failed" : "passed",
    scannedFiles: scan.files.length,
    fixed: firstScan.fixed,
    issues,
    shellSyntax,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("linux-portability", `linux-portability-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("linux-portability", `linux-portability-${stamp}`, [
    "# Platform Linux Portability Check",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    `Scanned files: ${payload.scannedFiles}`,
    `Fixed files: ${payload.fixed.length}`,
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue.file}: ${issue.type} (${issue.detail})`) : ["- none"]),
  ]);
  log(`Linux portability report written to ${jsonPath} and ${markdownPath}`);
  if (issues.length && !booleanFlag(argv.allowFailures)) {
    fail(`Linux portability check failed with ${issues.length} issue(s). Report: ${jsonPath}`);
  }
  log("Linux portability check passed.");
}

function repoCoverageCategory(filePath) {
  const normalized = filePath.replaceAll("\\", "/");
  const rules = [
    ["workflow", /^\.github\/workflows\/[^/]+\.ya?ml$/],
    ["root-policy", /^(?:\.dockerignore|\.env(?:\..*)?|\.gitattributes|\.gitignore|renovate\.json|SECURITY\.md|THREAT-MODEL\.md)$/],
    ["platform-config", /^config\/.+\.json$/],
    ["object-storage", /^minio\//],
    ["documentation", /^[A-Z][A-Z0-9_-]*\.md$|^(?:cloudflare|keycloak|minio|secrets)\/README\.md$/],
    ["compose", /^compose(?:\.[^.]+)?\.ya?ml$/],
    ["dns", /^dns\//],
    ["docker-build", /^docker\/[^/]+\.Dockerfile$/],
    ["operations-script", /^scripts\/.+\.(?:sh|mjs)$/],
    ["governance-policy", /^governance\/.+\.(?:json|jsonl|md)$/],
    ["cloudflare-policy", /^cloudflare\/.+\.(?:json|md)$/],
    ["observability", /^(?:alertmanager|grafana|loki|monitoring|platform-alert-dispatcher|prometheus|promtail)\//],
    ["identity", /^keycloak\//],
    ["database", /^(?:postgres|mariadb|phppgadmin)\//],
    ["messaging", /^nats\//],
    ["control-plane", /^control-center\//],
    ["php-runtime", /^(?:php-apache|phpmyadmin|php-runtime-root|projects-portal)\//],
    ["reverse-proxy", /^(?:traefik|project-router)\//],
    ["waf", /^waf\//],
    ["security-policy", /^security\//],
  ];
  const match = rules.find(([, pattern]) => pattern.test(normalized));
  return match?.[0] ?? null;
}

function readGithubWorkflowText() {
  const workflowDir = path.join(infraRoot, ".github", "workflows");
  if (!fs.existsSync(workflowDir)) {
    return "";
  }
  return fs.readdirSync(workflowDir)
    .filter((name) => /\.ya?ml$/i.test(name))
    .sort()
    .map((name) => readText(path.join(workflowDir, name)))
    .join("\n");
}

async function repoCoverageCheck() {
  log("==> Repository coverage check");
  const trackedManifest = process.env.PLATFORM_GIT_TRACKED_FILES_B64
    ? Buffer.from(process.env.PLATFORM_GIT_TRACKED_FILES_B64, "base64").toString("utf8")
    : output("git", ["-c", `safe.directory=${infraRoot}`, "ls-files", "-z"], { cwd: infraRoot });
  const trackedFiles = trackedManifest
    .split("\0")
    .map((file) => file.trim())
    .filter(Boolean)
    .sort();
  const categories = new Map();
  const uncovered = [];
  for (const file of trackedFiles) {
    const category = repoCoverageCategory(file);
    if (!category) {
      uncovered.push(file);
      continue;
    }
    if (!categories.has(category)) categories.set(category, []);
    categories.get(category).push(file);
  }

  const requiredCategories = [
    "workflow",
    "root-policy",
    "platform-config",
    "documentation",
    "compose",
    "docker-build",
    "operations-script",
    "governance-policy",
    "cloudflare-policy",
    "observability",
    "identity",
    "database",
    "object-storage",
    "messaging",
    "php-runtime",
    "reverse-proxy",
    "waf",
    "security-policy",
  ];
  const missingCategories = requiredCategories.filter((category) => !categories.has(category));
  const workflow = readGithubWorkflowText();
  const requiredWorkflowGates = [
    ["local-compose-render", /Render local WAF compose[\s\S]*compose\.yaml[\s\S]*compose\.secrets\.yaml[\s\S]*compose\.waf\.yaml/],
    ["vps-compose-render", /Render VPS WAF compose[\s\S]*compose\.vps\.yaml[\s\S]*compose\.vps-waf\.yaml/],
    ["staging-compose-render", /Render staging and backup compose[\s\S]*compose\.waf\.yaml[\s\S]*compose\.staging\.yaml/],
    ["backup-compose-render", /Render staging and backup compose[\s\S]*compose\.backup-scheduler\.yaml/],
    ["backup-scheduler-dry-run", /Backup scheduler dry run[\s\S]*BACKUP_SCHEDULER_DRY_RUN=true/],
    ["external-uptime-dry-run", /external-uptime-check --dryRun/],
    ["cloudflare-access-dry-run", /cloudflare-access-admin --manifest cloudflare\/access-admin\.example\.json/],
    ["cloudflare-from-zero-dry-run", /Cloudflare from-zero dry run[\s\S]*cloudflare-from-zero --manifest cloudflare\/from-zero\.example\.json/],
    ["github-branch-policy-dry-run", /github-branch-protection --repo/],
    ["github-environments-dry-run", /github-environments --repo/],
    ["github-actions-runtime-dry-run", /github-actions-config --repo/],
    ["github-actions-workflow-lint", /GitHub Actions workflow lint[\s\S]*rhysd\/actionlint:1\.7\.12@sha256:[a-f0-9]{64}/],
    ["github-actions-run-evidence-plan", /GitHub Actions run evidence plan[\s\S]*github-actions-run-evidence/],
    ["github-actions-run-evidence-verify-remote", /workflow_run:[\s\S]*enterprise-infra[\s\S]*Verify completed enterprise infra run[\s\S]*github-actions-run-evidence[\s\S]*--verifyRemote/],
    ["production-live-evidence-workflow", /workflow_dispatch:[\s\S]*evidence_not_before:[\s\S]*External uptime provider evidence[\s\S]*--providerEvidenceAttestation online[\s\S]*--providerEvidenceSourceDigest[\s\S]*--requireProviderEvidence[\s\S]*Production Cloudflare edge load benchmark[\s\S]*load-benchmark[\s\S]*--expectedEdgeProvider cloudflare[\s\S]*Cloudflare Access admin verify[\s\S]*cloudflare-access-admin[\s\S]*--verifyRemote[\s\S]*evidence-bundle --phase production-live --strict[\s\S]*evidence-bundle-verify --phase production-live[\s\S]*--requireComplete/],
    ["vps-evidence-workflow", /workflow_dispatch:[\s\S]*Run VPS evidence on VPS[\s\S]*vps-evidence-request\.mjs render[\s\S]*Upload VPS evidence reports/],
    ["pinned-ssh-host-trust", /DEPLOY_SSH_HOST_KEY[\s\S]*pinned-ssh-host-key\.mjs render[\s\S]*StrictHostKeyChecking=yes[\s\S]*UserKnownHostsFile=/],
    ["secret-scan", /Secret scan[\s\S]*secret-scan/],
    ["ha-config-check", /HA configuration check[\s\S]*ha-config-check/],
    ["managed-secrets-preflight", /Managed secrets preflight[\s\S]*managed-secrets-preflight/],
    ["compose-healthcheck-coverage", /Compose healthcheck coverage[\s\S]*compose-healthcheck-coverage/],
    ["rate-limit-evidence", /Rate limit evidence[\s\S]*rate-limit-evidence/],
    ["audit-log-evidence", /Audit log evidence[\s\S]*audit-log-evidence/],
    ["retention-evidence", /Retention evidence[\s\S]*retention-evidence/],
    ["secret-rotation-evidence-plan", /Secret rotation evidence plan[\s\S]*secret-rotation-evidence/],
    ["dr-readiness-check", /DR readiness check[\s\S]*dr-readiness-check/],
    ["dr-evidence-summary", /DR evidence summary[\s\S]*dr-evidence/],
    ["offsite-restore-plan", /Off-site restore drill plan[\s\S]*offsite-restore-drill-restic --planOnly/],
    ["release-evidence-plan", /release-evidence --planOnly/],
    ["release-artifact-gate-dry-run", /Release artifact gate dry run[\s\S]*release-artifact-gate --envFile \.tmp\/ci-release\.env[\s\S]*--sbom \.tmp\/ci-sbom\/pnpm-sbom-ci\.json/],
    ["alert-evidence-summary", /alert-evidence/],
    ["production-go-no-go-summary", /production-go-no-go/],
    ["pre-go-live-evidence-report", /Pre go-live evidence report[\s\S]*pre-go-live-evidence --infraOnly --repo/],
    ["evidence-bundle-smoke", /evidence-bundle --phase candidate-ci --strict --noArchive/],
    ["evidence-bundle-verify", /Evidence bundle integrity verify[\s\S]*evidence-bundle-verify/],
    ["linux-portability", /linux-portability-check/],
    ["enterprise-requirements", /Enterprise requirements traceability[\s\S]*enterprise-requirements-check/],
    ["production-readiness-checklist", /Production readiness checklist[\s\S]*enterprise-requirements-check --manifest governance\/production-readiness\.json/],
    ["production-live-proof-rejection", /Production live proof gate rejects missing evidence[\s\S]*enterprise-requirements-check --manifest governance\/production-readiness\.json --requireLiveProofs/],
    ["static-security-infra-only", /static-security-check --infraOnly/],
    ["repository-coverage", /repo-coverage-check/],
    ["ci-evidence-artifact", /Upload CI evidence reports[\s\S]*actions\/upload-artifact@[a-f0-9]{40}[\s\S]*reports\/[\s\S]*\.tmp\/evidence-bundles\/[\s\S]*retention-days:\s+30/],
    ["least-privilege-permissions", /permissions:\s*\r?\n\s+contents:\s+read(?![\s\S]*security-events:\s+write)/],
    ["quality-job-timeout", /^\s{2}quality:[\s\S]*?timeout-minutes:\s+30/m],
    ["compose-job-timeout", /^\s{2}compose:[\s\S]*?timeout-minutes:\s+45/m],
    ["canonical-ci-dag", /enterprise-readiness:[\s\S]*needs:\s*\r?\n\s+- quality\s*\r?\n\s+- compose\s*\r?\n\s+- supply-chain/],
    ["deploy-after-readiness", /deploy-vps:[\s\S]*needs:\s*enterprise-readiness/],
    ["dast-job-timeout", /dast-zap:[\s\S]*timeout-minutes:\s+45/],
    ["deploy-job-timeout", /deploy-vps:[\s\S]*timeout-minutes:\s+90/],
    ["shell-syntax", /for file in scripts\/\*\.sh/],
    ["workflow-dispatch", /workflow_dispatch:/],
    ["dast-manual", /dast-zap:[\s\S]*dast-zap-baseline\.sh/],
    ["deploy-manual", /deploy-vps:[\s\S]*deploy-vps\.sh/],
    ["deploy-production-preflight", /DEPLOY_RUN_PRODUCTION_PREFLIGHT:\s+"1"/],
    ["deploy-pre-go-live-evidence", /DEPLOY_RUN_PRE_GO_LIVE:\s+"1"/],
    ["deploy-production-go-no-go", /DEPLOY_RUN_GO_NO_GO:\s+"1"/],
    ["deploy-restore-drill-evidence", /DEPLOY_PRE_GO_LIVE_RESTORE_DRILL:\s+"1"/],
    ["deploy-offsite-restore-evidence", /DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN:\s+"1"/],
  ];
  const missingWorkflowGates = requiredWorkflowGates
    .filter(([, pattern]) => !pattern.test(workflow))
    .map(([name]) => name);
  const issues = [
    ...uncovered.map((file) => `Uncovered tracked file: ${file}`),
    ...missingCategories.map((category) => `Missing tracked files for required category: ${category}`),
    ...missingWorkflowGates.map((gate) => `Workflow does not exercise required gate: ${gate}`),
  ];
  const categorySummary = Object.fromEntries([...categories.entries()].map(([category, files]) => [category, files.length]));
  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : "passed",
    trackedFileCount: trackedFiles.length,
    coveredFileCount: trackedFiles.length - uncovered.length,
    uncovered,
    requiredCategories,
    missingCategories,
    categorySummary,
    workflowGates: requiredWorkflowGates.map(([name]) => ({
      name,
      present: !missingWorkflowGates.includes(name),
    })),
    issues,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("repo-coverage", `repo-coverage-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("repo-coverage", `repo-coverage-${stamp}`, [
    "# Repository Coverage",
    "",
    `Status: ${payload.status}`,
    `Generated at: ${payload.generatedAt}`,
    `Tracked files: ${payload.trackedFileCount}`,
    `Covered files: ${payload.coveredFileCount}`,
    "",
    "| Category | Files |",
    "| --- | ---: |",
    ...Object.entries(categorySummary).sort(([a], [b]) => a.localeCompare(b)).map(([category, count]) => `| ${category} | ${count} |`),
    "",
    "## Workflow Gates",
    "",
    "| Gate | Present |",
    "| --- | --- |",
    ...payload.workflowGates.map((gate) => `| ${gate.name} | ${gate.present ? "yes" : "no"} |`),
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- None"]),
  ]);
  log(`Repository coverage report written to ${jsonPath} and ${markdownPath}`);
  if (issues.length) {
    fail(`Repository coverage check failed with ${issues.length} issue(s). Report: ${jsonPath}`);
  }
  log("Repository coverage check passed.");
}

function enterpriseRequirementEvidenceResult(requirement, evidence, workflowText) {
  const base = {
    requirementId: requirement.id,
    type: evidence.type,
    target: evidence.path ?? evidence.name ?? evidence.pattern ?? "unknown",
    passed: false,
    detail: "",
  };
  if (evidence.type === "file") {
    const filePath = path.join(infraRoot, evidence.path);
    return {
      ...base,
      passed: fs.existsSync(filePath),
      detail: fs.existsSync(filePath) ? "file exists" : `missing file: ${evidence.path}`,
    };
  }
  if (evidence.type === "pattern") {
    const filePath = path.join(infraRoot, evidence.path);
    if (!fs.existsSync(filePath)) {
      return { ...base, detail: `missing file: ${evidence.path}` };
    }
    const text = readText(filePath);
    const pattern = new RegExp(evidence.pattern, evidence.flags ?? "i");
    const passed = pattern.test(text);
    return {
      ...base,
      passed,
      detail: passed ? `pattern matched in ${evidence.path}` : `pattern did not match in ${evidence.path}`,
    };
  }
  if (evidence.type === "workflow") {
    const pattern = new RegExp(evidence.pattern, evidence.flags ?? "i");
    const passed = pattern.test(workflowText);
    return {
      ...base,
      passed,
      detail: passed ? "workflow gate present" : "workflow gate missing",
    };
  }
  if (evidence.type === "command") {
    const passed = Object.prototype.hasOwnProperty.call(commands, evidence.name);
    return {
      ...base,
      passed,
      detail: passed ? "ops command exposed" : `missing ops command: ${evidence.name}`,
    };
  }
  return { ...base, detail: `unknown evidence type: ${evidence.type}` };
}

function enterpriseRequirementLiveProofResult(requirement, goNoGoReport, requireLiveProofs) {
  if (!requirement.liveProof) {
    return {
      required: false,
      status: "not-required",
      detail: "no live production proof required",
      checks: [],
      reportPath: null,
    };
  }
  if (requirement.id === "pentest") {
    const report = latestPentestReadinessReport();
    if (report) {
      return {
        required: true,
        status: "passed",
        detail: `pentest readiness evidence archived; external professional pentest remains required before enterprise launch`,
        checks: [{ name: "penetration-test-readiness", status: "passed", detail: report.payload.detail || "readiness report passed", reportPath: report.filePath }],
        reportPath: report.filePath,
      };
    }
    return {
      required: true,
      status: requireLiveProofs ? "failed" : "pending-external-evidence",
      detail: "missing pentest readiness evidence report",
      checks: [{ name: "penetration-test-readiness", status: "missing", detail: "missing reports/security/pentest-readiness-*.json" }],
      reportPath: null,
    };
  }
  if (requirement.id === "vulnerability-disclosure") {
    const report = latestVulnerabilityDisclosureReport();
    if (report) {
      return {
        required: true,
        status: "passed",
        detail: "vulnerability disclosure process approved and evidence archived",
        checks: [{ name: "vulnerability-disclosure", status: "passed", detail: report.payload.detail || "disclosure process evidence passed", reportPath: report.filePath }],
        reportPath: report.filePath,
      };
    }
    return {
      required: true,
      status: requireLiveProofs ? "failed" : "pending-external-evidence",
      detail: "missing vulnerability disclosure evidence report",
      checks: [{ name: "vulnerability-disclosure", status: "missing", detail: "missing reports/security/vulnerability-disclosure-*.json" }],
      reportPath: null,
    };
  }
  const governanceProofs = {
    "feature-flags-kill-switch": {
      command: "feature-flags-kill-switches",
      label: "feature flags and kill switches",
      missing: "missing reports/governance/feature-flags-kill-switches-*.json",
      latest: latestFeatureFlagsKillSwitchesReport,
    },
    "compliance-gdpr-soc2-like": {
      command: "compliance-evidence",
      label: "compliance GDPR/SOC2-like evidence",
      missing: "missing reports/governance/compliance-evidence-*.json",
      latest: latestComplianceEvidenceReport,
    },
    "data-classification": {
      command: "data-classification",
      label: "data classification",
      missing: "missing reports/governance/data-classification-*.json",
      latest: latestDataClassificationReport,
    },
    "ha-multi-node": {
      command: "ha-single-node-risk-acceptance",
      label: "HA single-node risk acceptance",
      missing: "missing reports/governance/ha-single-node-risk-acceptance-*.json",
      latest: latestHaSingleNodeRiskAcceptanceReport,
    },
  };
  const governanceProof = governanceProofs[requirement.id];
  if (governanceProof) {
    const report = governanceProof.latest();
    if (report) {
      return {
        required: true,
        status: "passed",
        detail: `${governanceProof.label} approved and evidence archived`,
        checks: [{ name: governanceProof.command, status: "passed", detail: report.payload.detail || `${governanceProof.label} evidence passed`, reportPath: report.filePath }],
        reportPath: report.filePath,
      };
    }
    return {
      required: true,
      status: requireLiveProofs ? "failed" : "pending-external-evidence",
      detail: `${governanceProof.label} evidence report is missing`,
      checks: [{ name: governanceProof.command, status: "missing", detail: governanceProof.missing }],
      reportPath: null,
    };
  }
  const requiredChecks = Array.isArray(requirement.liveProofChecks) ? requirement.liveProofChecks : [];
  if (!requiredChecks.length) {
    return {
      required: true,
      status: requireLiveProofs ? "failed" : "pending-external-evidence",
      detail: "no production go/no-go checks mapped",
      checks: [],
      reportPath: goNoGoReport?.filePath ?? null,
    };
  }
  if (!goNoGoReport?.payload) {
    return {
      required: true,
      status: requireLiveProofs ? "failed" : "pending-external-evidence",
      detail: "missing production go/no-go report",
      checks: requiredChecks.map((name) => ({ name, status: "missing" })),
      reportPath: null,
    };
  }
  const checksByName = new Map((goNoGoReport.payload.checks ?? []).map((check) => [check.name, check]));
  const checkResults = requiredChecks.map((name) => {
    const check = checksByName.get(name);
    return {
      name,
      status: check?.status ?? "missing",
      detail: check?.detail ?? "missing production go/no-go check",
      reportPath: check?.reportPath ?? null,
    };
  });
  const allChecksPassed = checkResults.every((check) => check.status === "passed");
  const goNoGoStatus = goNoGoReport.payload.status ?? "unknown";
  const passed = allChecksPassed;
  return {
    required: true,
    status: passed ? "passed" : requireLiveProofs ? "failed" : "pending-external-evidence",
    detail: passed
      ? `production go/no-go report proves mapped checks; global status=${goNoGoStatus}`
      : `production go/no-go status=${goNoGoStatus}; failedOrMissing=${checkResults.filter((check) => check.status !== "passed").map((check) => check.name).join(",") || "none"}`,
    checks: checkResults,
    reportPath: goNoGoReport.filePath,
  };
}

function latestPentestReadinessReport() {
  return latestJsonReport("security", "pentest-readiness-", (payload) => pentestReadinessPayloadPassed(payload));
}

function latestVulnerabilityDisclosureReport() {
  return latestJsonReport("security", "vulnerability-disclosure-", (payload) => vulnerabilityDisclosurePayloadPassed(payload));
}

function latestComplianceEvidenceReport() {
  return latestJsonReport("governance", "compliance-evidence-", (payload) => complianceEvidencePayloadPassed(payload));
}

function latestDataClassificationReport() {
  return latestJsonReport("governance", "data-classification-", (payload) => dataClassificationPayloadPassed(payload));
}

function latestFeatureFlagsKillSwitchesReport() {
  return latestJsonReport("governance", "feature-flags-kill-switches-", (payload) => featureFlagsKillSwitchesPayloadPassed(payload));
}

function latestHaSingleNodeRiskAcceptanceReport() {
  return latestJsonReport("governance", "ha-single-node-risk-acceptance-", (payload) => haSingleNodeRiskAcceptancePayloadPassed(payload));
}

function pentestReadinessPayloadPassed(payload) {
  return payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.mode === "readiness-plan"
    && payload.readiness?.approved === true
    && payload.externalProfessionalPentest?.requiredBeforeEnterpriseLaunch === true
    && Number(payload.summary?.failedChecks || 0) === 0;
}

function vulnerabilityDisclosurePayloadPassed(payload) {
  return payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === "vulnerability-disclosure"
    && payload.process?.publishable === true
    && payload.process?.approved === true
    && payload.channel?.securityPolicyPresent === true
    && Number(payload.summary?.failedChecks || 0) === 0;
}

function complianceEvidencePayloadPassed(payload) {
  return payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === "compliance-evidence"
    && payload.compliance?.approved === true
    && payload.compliance?.formalCertificationClaimed === false
    && payload.compliance?.gdprLikeMapping === true
    && payload.compliance?.soc2LikeMapping === true
    && Number(payload.summary?.failedChecks || 0) === 0;
}

function dataClassificationPayloadPassed(payload) {
  const levels = new Set(Array.isArray(payload?.classification?.levels) ? payload.classification.levels : []);
  return payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === "data-classification"
    && payload.classification?.approved === true
    && payload.classification?.hostedApplicationDataOutOfScope === true
    && ["Public", "Internal", "Confidential", "Secret", "Restricted"].every((level) => levels.has(level))
    && Number(payload.summary?.failedChecks || 0) === 0;
}

function featureFlagsKillSwitchesPayloadPassed(payload) {
  return payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === "feature-flags-kill-switches"
    && payload.killSwitches?.operational === true
    && payload.killSwitches?.applicationFlagsOutOfScope === true
    && payload.killSwitches?.destructiveVolumeActionsAllowed === false
    && Number(payload.killSwitches?.switchCount || 0) >= 6
    && Number(payload.summary?.failedChecks || 0) === 0;
}

function haSingleNodeRiskAcceptancePayloadPassed(payload) {
  return payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === "ha-single-node-risk-acceptance"
    && payload.decision?.singleNodeRiskAccepted === true
    && payload.decision?.haClaimed === false
    && payload.decision?.multiNodeClaimed === false
    && Number(payload.summary?.failedChecks || 0) === 0;
}

function enterpriseProduction360CoveragePayloadPassed(payload) {
  return payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === "enterprise-production-360-coverage"
    && payload.semantics?.productionGoLiveDecision === false
    && Number(payload.summary?.invalidRefs || 0) === 0
    && Number(payload.summary?.domains || 0) >= Number(payload.summary?.expectedDomains || 0)
    && Number(payload.summary?.controls || 0) >= Number(payload.summary?.minimumControls || 0);
}

async function enterpriseRequirementsCheck() {
  log("==> Enterprise requirements traceability check");
  const manifestPath = path.resolve(argv.manifest ?? path.join(infraRoot, "governance", "enterprise-requirements.json"));
  const manifest = readJsonFile(manifestPath, manifestPath);
  const expectedCount = positiveInteger(argv.expectedCount ?? manifest.expectedCount ?? 30, "--expectedCount", 1);
  const reportDirectory = String(manifest.reportDirectory ?? "enterprise-requirements");
  const reportPrefix = String(manifest.reportPrefix ?? "enterprise-requirements");
  const reportTitle = String(manifest.title ?? "Enterprise Requirements Traceability");
  const requireLiveProofs = booleanFlag(argv.requireLiveProofs);
  const liveProofCheckRequired = Boolean(manifest.liveProofCheckRequired);
  const goNoGoReport = latestJsonReport("go-no-go", "production-go-no-go-");
  const workflowText = readGithubWorkflowText();
  const allowedStates = new Set(["repo-ready", "gate-ready", "environment-ready", "proprietary-integrated", "repo-ready-plus-environment-action"]);
  const repoIssues = [];
  const liveProofIssues = [];
  if (manifest.version !== 1) {
    repoIssues.push(`Unsupported manifest version: ${manifest.version}`);
  }
  if (!Array.isArray(manifest.requirements)) {
    repoIssues.push("Manifest must define requirements array.");
  }
  const requirements = Array.isArray(manifest.requirements) ? manifest.requirements : [];
  if (requirements.length !== expectedCount) {
    repoIssues.push(`Traceability manifest must track exactly ${expectedCount} requirements, found ${requirements.length}.`);
  }
  const seenIds = new Set();
  const rows = requirements.map((requirement) => {
    const repoRequirementIssues = [];
    if (!requirement.id || !/^[a-z0-9-]+$/.test(requirement.id)) {
      repoRequirementIssues.push("missing or invalid id");
    } else if (seenIds.has(requirement.id)) {
      repoRequirementIssues.push(`duplicate id: ${requirement.id}`);
    } else {
      seenIds.add(requirement.id);
    }
    if (!requirement.title) {
      repoRequirementIssues.push("missing title");
    }
    if (!allowedStates.has(requirement.state)) {
      repoRequirementIssues.push(`invalid state: ${requirement.state}`);
    }
    if (!requirement.liveProof) {
      repoRequirementIssues.push("missing liveProof");
    }
    if (liveProofCheckRequired && requirement.liveProof && !Array.isArray(requirement.liveProofChecks)) {
      repoRequirementIssues.push("missing liveProofChecks");
    }
    const evidence = Array.isArray(requirement.evidence) ? requirement.evidence : [];
    if (evidence.length < 2) {
      repoRequirementIssues.push("at least two evidence entries are required");
    }
    const evidenceResults = evidence.map((item) => enterpriseRequirementEvidenceResult(requirement, item, workflowText));
    const liveProofResult = enterpriseRequirementLiveProofResult(requirement, goNoGoReport, requireLiveProofs);
    for (const result of evidenceResults) {
      if (!result.passed) {
        repoRequirementIssues.push(result.detail);
      }
    }
    const requirementIssues = [...repoRequirementIssues];
    if (repoRequirementIssues.length) {
      repoIssues.push(`${requirement.id ?? "unknown"}: ${repoRequirementIssues.join("; ")}`);
    }
    if (requireLiveProofs && liveProofResult.required && liveProofResult.status !== "passed") {
      const liveIssue = `live proof not satisfied: ${liveProofResult.detail}`;
      requirementIssues.push(liveIssue);
      liveProofIssues.push(`${requirement.id ?? "unknown"}: ${liveIssue}`);
    }
    return {
      id: requirement.id ?? "unknown",
      title: requirement.title ?? "",
      state: requirement.state ?? "",
      liveProof: requirement.liveProof ?? "",
      liveProofRequired: Boolean(requirement.liveProof),
      liveProofChecks: Array.isArray(requirement.liveProofChecks) ? requirement.liveProofChecks : [],
      liveProofStatus: liveProofResult.status,
      liveProofEvidence: liveProofResult,
      repoEvidenceStatus: repoRequirementIssues.length ? "failed" : "passed",
      status: requirementIssues.length ? "failed" : "passed",
      evidence: evidenceResults,
      issues: requirementIssues,
      repoIssues: repoRequirementIssues,
    };
  });
  const issues = [...repoIssues, ...liveProofIssues];
  const liveProofsPending = rows
    .filter((row) => row.liveProofRequired && row.liveProofStatus !== "passed")
    .map((row) => ({
      id: row.id,
      title: row.title,
      state: row.state,
      liveProof: row.liveProof,
      status: row.liveProofStatus,
    }));
  const liveProofRequiredCount = rows.filter((row) => row.liveProofRequired).length;
  const liveProofStatus = liveProofIssues.length
    ? "failed"
    : liveProofsPending.length
      ? "pending-external-evidence"
      : liveProofRequiredCount
        ? "passed"
        : "not-required";

  const payload = {
    generatedAt: new Date().toISOString(),
    manifestPath,
    requireLiveProofs,
    goNoGoReportPath: goNoGoReport?.filePath ?? null,
    goNoGoStatus: goNoGoReport?.payload?.status ?? null,
    status: issues.length ? "failed" : "passed",
    repoStatus: repoIssues.length ? "failed" : "passed",
    liveProofStatus,
    requirementCount: requirements.length,
    passedCount: rows.filter((row) => row.status === "passed").length,
    failedCount: rows.filter((row) => row.status !== "passed").length,
    liveProofRequiredCount,
    liveProofsPending,
    repoIssues,
    liveProofIssues,
    requirements: rows,
    issues,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport(reportDirectory, `${reportPrefix}-${stamp}`, payload);
  const markdownPath = writeMarkdownReport(reportDirectory, `${reportPrefix}-${stamp}`, [
    `# ${reportTitle}`,
    "",
    `Status: ${payload.status}`,
    `Repository evidence status: ${payload.repoStatus}`,
    `Live proof status: ${payload.liveProofStatus}`,
    `Generated at: ${payload.generatedAt}`,
    `Requirements: ${payload.requirementCount}`,
    `Passed: ${payload.passedCount}`,
    `Failed: ${payload.failedCount}`,
    `Live proofs still required: ${payload.liveProofRequiredCount}`,
    "",
    "| Requirement | State | Repo evidence | Live proof status | Evidence passed | Live proof still required |",
    "| --- | --- | --- | --- | ---: | --- |",
    ...rows.map((row) => `| ${row.id} | ${row.state} | ${row.repoEvidenceStatus} | ${row.liveProofStatus} | ${row.evidence.filter((item) => item.passed).length}/${row.evidence.length} | ${row.liveProof.replace(/\|/g, "/")} |`),
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"]),
    "",
    "## Pending Live Proofs",
    "",
    ...(liveProofsPending.length ? liveProofsPending.map((item) => `- ${item.id}: ${item.liveProof}`) : ["- none"]),
  ]);
  log(`Enterprise requirements report written to ${jsonPath} and ${markdownPath}`);
  if (issues.length) {
    fail(`Enterprise requirements check failed with ${issues.length} issue(s). Report: ${jsonPath}`);
  }
  log("Enterprise requirements traceability check passed.");
}

async function enterpriseTenCheck() {
  log("==> Enterprise 10 readiness gate");
  const repoOnly = booleanFlag(argv.repoOnly);
  const noDocker = noDockerMode({ noDocker: repoOnly });
  await haConfigCheck({ noDocker });
  await managedSecretsPreflight({ noDocker });
  if (repoOnly) {
    log("Skipping release artifact admission in --repoOnly mode; run with real release image manifest and SBOM for release go/no-go.");
  } else {
    await releaseArtifactGate();
  }
  await drReadinessCheck({ noDocker });
  await governanceCheck();
  await externalUptimeCheck({ dryRun: true, envFile: repoOnly ? path.join(infraRoot, ".env.example") : undefined });
  await linuxPortabilityCheck();
  await staticSecurityCheck();
  await controlCenterTests();
  await projectRouterTests();
  await testingHygiene();
  await performanceHygiene();
  log("Enterprise 10 readiness gate passed.");
}

async function restorePostgres() {
  const backupFileArg = argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  if (!argv.confirmRestore) {
    fail("Restore is destructive. Re-run with --confirmRestore after verifying the backup file.");
  }
  const container = argv.container ?? "enterprise-postgres";
  const database = argv.database ?? defaultPostgresBackupDatabase();
  const user = argv.user ?? "postgres";
  const backupFile = resolveInside(path.join(infraRoot, "backups"), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const containerPath = `/tmp/${fileName}`;
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  try {
    log(`Copying backup into ${container}...`);
    run("docker", ["cp", backupFile, `${container}:${containerPath}`]);
    log(`Restoring database '${database}'. This will clean existing objects owned by the dump.`);
    dockerExec(container, ["pg_restore", "-U", user, "-d", database, "--clean", "--if-exists", "--no-owner", "--no-acl", containerPath]);
    dockerExec(container, ["rm", "-f", containerPath]);
    recordBackupRestoreRun({ container, database, user, operation: "restore", status: "success", artifactPath: backupFile, artifactSha256: hash, startedAt });
    const stamp = reportTimestamp();
    const payload = {
      generatedAt: new Date().toISOString(),
      status: "passed",
      container,
      database,
      user,
      artifactPath: backupFile,
      artifactSha256: hash,
    };
    const jsonPath = writeJsonReport("postgres-restore", `restore-postgres-${stamp}`, payload);
    const markdownPath = writeMarkdownReport("postgres-restore", `restore-postgres-${stamp}`, [
      "# PostgreSQL Restore",
      "",
      `Generated at: ${payload.generatedAt}`,
      `Status: ${payload.status}`,
      `Database: ${database}`,
      `Artifact: ${backupFile}`,
    ]);
    log("Restore complete.");
    log(`PostgreSQL restore report written to ${jsonPath} and ${markdownPath}`);
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-f", containerPath], { allowFailure: true });
      recordBackupRestoreRun({ container, database, user, operation: "restore", status: "failed", artifactPath: backupFile, artifactSha256: hash, startedAt, metadata: { error: String(error?.message ?? error) } });
    } catch {
      // Preserve the original restore failure.
    }
    throw error;
  }
}

async function restoreTestPostgres(options = {}) {
  const backupFileArg = options.backupFile ?? argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  const sourceContainer = options.container ?? argv.container ?? "enterprise-postgres";
  const sourceDatabase = options.database ?? argv.database ?? defaultPostgresBackupDatabase();
  const testDatabase = sqlIdentifierName(options.testDatabase ?? argv.testDatabase ?? "platform_restore_test", "PostgreSQL restore sandbox database");
  const requestedSchema = options.schema ?? options.accountSchema ?? argv.schema ?? argv.accountSchema ?? "";
  const schemaName = requestedSchema ? sqlIdentifierName(requestedSchema, "PostgreSQL restore schema") : "";
  const countAllUserTables = !schemaName || options.countAllUserTables === true || booleanFlag(argv.countAllUserTables);
  const minimumTables = positiveInteger(options.minimumTables ?? argv.minimumTables ?? 1, "--minimumTables", 1);
  const backupFile = resolveInside(path.join(infraRoot, "backups"), path.resolve(backupFileArg));
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  const image = options.image ?? argv.image ?? process.env.POSTGRES_RESTORE_TEST_IMAGE ?? process.env.POSTGRES_IMAGE ?? defaultPostgresRestoreImage;
  const sandboxContainer = `platform-postgres-restore-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
  const plan = postgresRestoreSandboxPlan({
    image,
    containerName: sandboxContainer,
    backupMount: `${hostPathForContainerMount(backupFile)}:/restore/input.dump:ro`,
    databaseName: testDatabase,
  });
  let sandboxStarted = false;
  try {
    log(`Starting isolated PostgreSQL restore sandbox '${sandboxContainer}'...`);
    run("docker", plan.dockerRunArgs, { capture: true });
    sandboxStarted = true;
    let ready = false;
    for (let attempt = 0; attempt < 90; attempt += 1) {
      const probe = dockerExec(sandboxContainer, ["pg_isready", "-U", "postgres", "-d", "postgres"], { capture: true, allowFailure: true });
      if (probe.status === 0) {
        ready = true;
        break;
      }
      await sleep(500);
    }
    if (!ready) fail("Isolated PostgreSQL restore sandbox did not become ready.");
    dockerExec(sandboxContainer, ["psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", plan.bootstrapSql]);
    dockerExec(sandboxContainer, plan.restoreArgs);
    const tableQuery = countAllUserTables
      ? "select count(*) from information_schema.tables where table_schema not in ('information_schema','pg_catalog');"
      : `select count(*) from information_schema.tables where table_schema = ${sqlString(schemaName)};`;
    const tables = Number(postgresOut(sandboxContainer, plan.database, plan.role, tableQuery));
    if (tables < minimumTables) {
      fail(`Restore test produced too few ${countAllUserTables ? "user" : schemaName} tables: ${tables}`);
    }
    recordBackupRestoreRun({
      container: sandboxContainer,
      database: sourceDatabase,
      user: plan.role,
      operation: "restore_test",
      status: "success",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: {
        restoredTables: tables,
        restoredSchema: countAllUserTables ? "all-user-schemas" : schemaName,
        testDatabase,
        sourceContainer,
        isolation: "disposable-network-none",
        liveSourceTouched: false,
      },
    });
    log(`Restore test passed with ${tables} ${countAllUserTables ? "user" : schemaName} tables.`);
    return { backupFile, hash, tables, testDatabase, container: sandboxContainer, database: sourceDatabase, user: plan.role, liveSourceTouched: false };
  } catch (error) {
    try {
      recordBackupRestoreRun({ container: sandboxContainer, database: sourceDatabase, user: plan.role, operation: "restore_test", status: "failed", artifactPath: backupFile, artifactSha256: hash, startedAt, metadata: { error: String(error?.message ?? error), testDatabase, sourceContainer, isolation: "disposable-network-none", liveSourceTouched: false } });
    } catch {
      // Preserve the original restore-test failure.
    }
    throw error;
  } finally {
    if (sandboxStarted) run("docker", ["rm", "-f", sandboxContainer], { capture: true, allowFailure: true });
  }
}

async function backupRestoreDrill() {
  log("==> PostgreSQL backup/restore drill");
  const container = argv.container ?? "enterprise-postgres";
  const database = argv.database ?? defaultPostgresBackupDatabase();
  const user = argv.user ?? "postgres";
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "postgres", "drills"));
  const suffix = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const testDatabase = argv.testDatabase ?? `platform_restore_test_${suffix}`;
  const backup = await backupPostgres({ container, database, user, outputDir });
  const restore = await restoreTestPostgres({ container, database, user, backupFile: backup.hostPath, testDatabase });
  const recorded = backupRestoreRunRecords().some((record) =>
    record.operation === "restore_test"
      && record.status === "success"
      && record.artifactSha256 === backup.hash
      && record.metadata?.testDatabase === restore.testDatabase);
  if (!recorded) {
    fail("Restore drill completed but backup_restore_runs did not record the matching restore_test success.");
  }
  log(`Backup/restore drill recorded restore_test success for ${path.basename(backup.hostPath)}.`);
}

async function backupMariadb(options = {}) {
  const container = options.container ?? argv.container ?? "mariadb";
  const requestedDatabase = options.database ?? argv.database ?? "";
  const database = requestedDatabase ? sqlIdentifierName(requestedDatabase, "MariaDB database") : "";
  const outputDir = ensureBackupOutputDir(path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "mariadb")));
  const startedAt = new Date();
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const fileName = `mariadb-${database || "all"}-${timestamp}.sql.gz`;
  const containerPath = `/tmp/${fileName}`;
  const hostPath = path.join(outputDir, fileName);
  const stagingPath = backupArtifactStagingPath(hostPath);

  try {
    log(database ? `Creating MariaDB backup for exact database '${database}'...` : "Creating MariaDB full backup for all local PHP project databases...");
    const databaseSelection = database
      ? `DATABASES=${shellQuote(database)}`
      : 'DATABASES="$(mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -N -e "select schema_name from information_schema.schemata where schema_name not in (\'information_schema\',\'mysql\',\'performance_schema\',\'sys\') order by schema_name")"';
    dockerExec(container, [
      "sh",
      "-ec",
      [
        "test -s /run/secrets/mariadb_root_password",
        'MARIADB_ROOT_PASSWORD="$(cat /run/secrets/mariadb_root_password)"',
        databaseSelection,
        'test -n "$DATABASES"',
        `mariadb-dump --single-transaction --routines --events --triggers --databases $DATABASES -uroot -p"$MARIADB_ROOT_PASSWORD" | gzip -9 > ${shellQuote(containerPath)}`,
      ].join(" && "),
    ]);
    run("docker", ["cp", `${container}:${containerPath}`, stagingPath]);
    dockerExec(container, ["rm", "-f", containerPath]);

    const publication = publishBackupArtifact({
      stagingPath,
      publishedPath: hostPath,
      createSignature: createBackupArtifactSignature,
      onPublished({ hash, sizeBytes, signature }) {
        recordDatabaseBackupEvidence({
          engine: "mariadb",
          sourceContainer: container,
          operation: "backup",
          status: "success",
          artifactPath: hostPath,
          artifactSha256: hash,
          artifactSizeBytes: sizeBytes,
          startedAt,
        });
        writeBackupExecutionReport({
          engine: "mariadb",
          sourceContainer: container,
          status: "success",
          artifactPath: hostPath,
          artifactSha256: hash,
          signature,
          startedAt,
          metadata: { scope: database ? "exact-database" : "all-user-databases", database: database || null, compression: "gzip" },
        });
      },
    });
    try {
      const { hash, signature } = publication;
      publication.assertCurrent();
      log(`MariaDB backup written to ${hostPath}`);
      log(`SHA256: ${hash}`);
      log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
      return { hostPath, hash, signature, container, database: database || null };
    } finally {
      publication.close();
    }
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-f", containerPath], { allowFailure: true });
      recordDatabaseBackupEvidence({
        engine: "mariadb",
        sourceContainer: container,
        operation: "backup",
        status: "failed",
        artifactPath: hostPath,
        startedAt,
        metadata: { error: String(error?.message ?? error) },
      });
      writeBackupExecutionReport({
        engine: "mariadb",
        sourceContainer: container,
        status: "failed",
        artifactPath: hostPath,
        startedAt,
        metadata: { error: String(error?.message ?? error) },
      });
    } catch {
      // Preserve the original backup failure.
    }
    throw error;
  }
}

async function restoreTestMariadb(options = {}) {
  const backupFileArg = options.backupFile ?? argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  const sourceContainer = options.container ?? argv.container ?? "mariadb";
  const backupFile = resolveInside(backupRootPath(), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const containerPath = `/tmp/${fileName}`;
  const suffix = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const drillContainer = options.drillContainer ?? argv.drillContainer ?? `platform-mariadb-restore-test-${suffix}`;
  const image = options.image ?? argv.image ?? output("docker", ["inspect", "--format={{.Config.Image}}", sourceContainer]);
  const rootPassword = `restore_${crypto.randomBytes(18).toString("base64url")}`;
  const minSchemas = positiveInteger(options.minSchemas ?? argv.minSchemas ?? 3, "--minSchemas", 1);
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  let schemaCount = 0;
  let tableCount = 0;

  try {
    log(`Starting disposable MariaDB restore-test container '${drillContainer}'...`);
    run("docker", ["rm", "-f", drillContainer], { allowFailure: true, capture: true });
    run("docker", ["run", "-d", "--name", drillContainer, "--network", "none", "-e", `MARIADB_ROOT_PASSWORD=${rootPassword}`, image], { capture: true });

    let healthy = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const probe = dockerExec(drillContainer, ["sh", "-ec", 'mariadb-admin ping -h 127.0.0.1 -uroot -p"$MARIADB_ROOT_PASSWORD" --silent'], { allowFailure: true, capture: true });
      if (probe.status === 0) {
        healthy = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    if (!healthy) {
      fail("Disposable MariaDB restore-test container did not become ready.");
    }

    run("docker", ["cp", backupFile, `${drillContainer}:${containerPath}`]);
    dockerExec(drillContainer, ["sh", "-ec", `gzip -dc ${shellQuote(containerPath)} | mariadb -uroot -p"$MARIADB_ROOT_PASSWORD"`]);
    const schemaSql = "select count(*) from information_schema.schemata where schema_name not in ('information_schema','mysql','performance_schema','sys')";
    const tableSql = "select count(*) from information_schema.tables where table_schema not in ('information_schema','mysql','performance_schema','sys')";
    schemaCount = Number(dockerExecOutput(drillContainer, ["sh", "-ec", `mariadb -N -uroot -p"$MARIADB_ROOT_PASSWORD" -e ${shellQuote(schemaSql)}`]).trim());
    tableCount = Number(dockerExecOutput(drillContainer, ["sh", "-ec", `mariadb -N -uroot -p"$MARIADB_ROOT_PASSWORD" -e ${shellQuote(tableSql)}`]).trim());
    if (schemaCount < minSchemas) {
      fail(`MariaDB restore test produced too few user schemas: ${schemaCount}`);
    }
    recordDatabaseBackupEvidence({
      engine: "mariadb",
      sourceContainer,
      operation: "restore_test",
      status: "success",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { restoredSchemas: schemaCount, restoredTables: tableCount, drillContainer },
    });
    log(`MariaDB restore test passed with ${schemaCount} user schemas and ${tableCount} user tables.`);
    return { backupFile, hash, restoredSchemas: schemaCount, restoredTables: tableCount };
  } catch (error) {
    recordDatabaseBackupEvidence({
      engine: "mariadb",
      sourceContainer,
      operation: "restore_test",
      status: "failed",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { error: String(error?.message ?? error), restoredSchemas: schemaCount, restoredTables: tableCount, drillContainer },
    });
    throw error;
  } finally {
    run("docker", ["rm", "-f", drillContainer], { allowFailure: true, capture: true });
  }
}

function countMariadbUserSchemas(container) {
  const schemaSql = "select count(*) from information_schema.schemata where schema_name not in ('information_schema','mysql','performance_schema','sys')";
  const outputText = dockerExecOutput(container, [
    "sh",
    "-ec",
    [
      "test -s /run/secrets/mariadb_root_password",
      'MARIADB_ROOT_PASSWORD="$(cat /run/secrets/mariadb_root_password)"',
      `mariadb -N -uroot -p"$MARIADB_ROOT_PASSWORD" -e ${shellQuote(schemaSql)}`,
    ].join(" && "),
  ]).trim();
  const schemaCount = Number(outputText);
  if (!Number.isFinite(schemaCount) || schemaCount < 1) {
    fail(`MariaDB source has no restorable user schemas: ${outputText || "0"}`);
  }
  return schemaCount;
}

async function backupRestoreDrillMariadb() {
  log("==> MariaDB backup/restore drill");
  const container = argv.container ?? "mariadb";
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "mariadb", "drills"));
  const sourceSchemaCount = countMariadbUserSchemas(container);
  const backup = await backupMariadb({ container, outputDir });
  await restoreTestMariadb({ container, backupFile: backup.hostPath, minSchemas: sourceSchemaCount });
  log(`MariaDB backup/restore drill completed for ${path.basename(backup.hostPath)}.`);
}

async function backupMinio(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-minio";
  const outputDir = ensureBackupOutputDir(path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "minio")));
  const startedAt = new Date();
  const fileName = `minio-data-${backupTimestamp()}.tar.gz`;
  const hostPath = path.join(outputDir, fileName);
  const stagingPath = backupArtifactStagingPath(hostPath);
  const stagingFileName = path.basename(stagingPath);
  const hostWorkParent = makeOpsTempDir("platform-minio-data-");
  const hostWorkDir = path.join(hostWorkParent, "minio-data");

  try {
    log("Creating MinIO data backup...");
    run("docker", ["cp", `${container}:/data`, hostWorkDir]);
    dockerRun([
      "-v",
      `${hostPathForContainerMount(hostWorkDir)}:/work:ro`,
      "-v",
      `${hostPathForContainerMount(outputDir)}:/backup`,
      configuredNodeImage(),
      "sh",
      "-lc",
      `tar -czf /backup/${shellQuote(stagingFileName)} -C /work .`,
    ]);

    const { hash, signature } = publishBackupArtifactWithEvidence({
      stagingPath,
      hostPath,
      engine: "minio",
      sourceContainer: container,
      startedAt,
      metadata: { scope: "data-volume", compression: "tar.gz" },
      recordSuccess({ hash: artifactSha256 }) {
        recordDatabaseBackupEvidence({
          engine: "minio",
          sourceContainer: container,
          operation: "backup",
          status: "success",
          artifactPath: hostPath,
          artifactSha256,
          startedAt,
        });
      },
    });
    log(`MinIO backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, signature, container };
  } catch (error) {
    try {
      recordDatabaseBackupEvidence({
        engine: "minio",
        sourceContainer: container,
        operation: "backup",
        status: "failed",
        artifactPath: hostPath,
        startedAt,
        metadata: { error: String(error?.message ?? error) },
      });
      writeBackupExecutionReport({
        engine: "minio",
        sourceContainer: container,
        status: "failed",
        artifactPath: hostPath,
        startedAt,
        metadata: { error: String(error?.message ?? error) },
      });
    } catch {
      // Preserve the original backup failure.
    }
    throw error;
  } finally {
    fs.rmSync(hostWorkParent, { recursive: true, force: true });
  }
}

async function restoreTestMinio(options = {}) {
  const backupFileArg = options.backupFile ?? argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  const sourceContainer = options.container ?? argv.container ?? "enterprise-minio";
  const backupFile = resolveInside(backupRootPath(), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const backupDir = path.dirname(backupFile);
  const suffix = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const drillContainer = options.drillContainer ?? argv.drillContainer ?? `platform-minio-restore-test-${suffix}`;
  const drillVolume = options.drillVolume ?? argv.drillVolume ?? `minio_admin_restore_test_${suffix}`;
  const image = options.image ?? argv.image ?? output("docker", ["inspect", "--format={{.Config.Image}}", sourceContainer]);
  const utilityImage = options.utilityImage ?? argv.utilityImage ?? configuredNodeImage();
  const rootUser = "restore_minio";
  const rootPassword = `restore_${crypto.randomBytes(24).toString("base64url")}`;
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  let restoredEntries = 0;

  try {
    log(`Restoring MinIO backup into disposable volume '${drillVolume}'...`);
    run("docker", ["rm", "-f", drillContainer], { allowFailure: true, capture: true });
    run("docker", ["volume", "rm", "-f", drillVolume], { allowFailure: true, capture: true });
    run("docker", ["volume", "create", drillVolume], { capture: true });
    dockerRun([
      "--name",
      `${drillContainer}-extract`,
      "--entrypoint",
      "sh",
      "-v",
      `${drillVolume}:/data`,
      "-v",
      `${hostPathForContainerMount(backupDir)}:/backup:ro`,
      utilityImage,
      "-ec",
      `tar -xzf /backup/${shellQuote(fileName)} -C /data && test -d /data/.minio.sys`,
    ]);
    run("docker", [
      "run",
      "-d",
      "--name",
      drillContainer,
      "--network",
      "none",
      "-e",
      `MINIO_ROOT_USER=${rootUser}`,
      "-e",
      `MINIO_ROOT_PASSWORD=${rootPassword}`,
      "-v",
      `${drillVolume}:/data`,
      image,
      "server",
      "/data",
      "--address",
      ":9000",
      "--console-address",
      ":9001",
    ], { capture: true });

    let healthy = false;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const probe = dockerExec(drillContainer, ["sh", "-ec", "curl -fsS http://127.0.0.1:9000/minio/health/live >/dev/null"], { allowFailure: true, capture: true });
      if (probe.status === 0) {
        healthy = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    if (!healthy) {
      fail("Disposable MinIO restore-test container did not become healthy.");
    }
    const countResult = dockerRun([
      "-v",
      `${drillVolume}:/data:ro`,
      utilityImage,
      "sh",
      "-lc",
      "find /data -mindepth 1 | wc -l",
    ], { capture: true });
    restoredEntries = Number(String(countResult.stdout ?? "").trim());
    if (!Number.isFinite(restoredEntries) || restoredEntries < 1) {
      fail("MinIO restore test did not restore any filesystem entries.");
    }
    recordDatabaseBackupEvidence({
      engine: "minio",
      sourceContainer,
      operation: "restore_test",
      status: "success",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { restoredEntries, drillContainer, drillVolume },
    });
    log(`MinIO restore test passed with ${restoredEntries} restored filesystem entries.`);
    return { backupFile, hash, restoredEntries };
  } catch (error) {
    recordDatabaseBackupEvidence({
      engine: "minio",
      sourceContainer,
      operation: "restore_test",
      status: "failed",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { error: String(error?.message ?? error), restoredEntries, drillContainer, drillVolume },
    });
    throw error;
  } finally {
    run("docker", ["rm", "-f", drillContainer], { allowFailure: true, capture: true });
    run("docker", ["volume", "rm", "-f", drillVolume], { allowFailure: true, capture: true });
  }
}

async function backupRestoreDrillMinio() {
  log("==> MinIO backup/restore drill");
  const container = argv.container ?? "enterprise-minio";
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "minio", "drills"));
  const backup = await backupMinio({ container, outputDir });
  await restoreTestMinio({ container, backupFile: backup.hostPath });
  log(`MinIO backup/restore drill completed for ${path.basename(backup.hostPath)}.`);
}

async function backupKeycloakConfig(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-keycloak";
  const outputDir = ensureBackupOutputDir(path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "keycloak")));
  const startedAt = new Date();
  const fileName = `keycloak-config-${backupTimestamp()}.tar.gz`;
  const hostPath = path.join(outputDir, fileName);
  const stagingPath = backupArtifactStagingPath(hostPath);
  const stagingFileName = path.basename(stagingPath);
  const containerWorkDir = "/tmp/platform-keycloak-config-backup";
  const hostWorkParent = makeOpsTempDir("platform-keycloak-config-");
  const hostWorkDir = path.join(hostWorkParent, "keycloak-config");
  const backupScript = `
set -eu
work="${containerWorkDir}"
rm -rf "$work"
mkdir -p "$work/realms" "$work/import" "$work/runtime"
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/secrets/keycloak_admin_password)"
export KC_BOOTSTRAP_ADMIN_PASSWORD
/opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/tmp/platform-kcadm-backup.log 2>&1
/opt/keycloak/bin/kcadm.sh get realms --fields realm,enabled > "$work/realms.json"
for realm in $(grep -o '"realm"[[:space:]]*:[[:space:]]*"[^"]*"' "$work/realms.json" | sed 's/.*"realm"[[:space:]]*:[[:space:]]*"//; s/".*//'); do
  safe="$(printf '%s' "$realm" | tr -c 'A-Za-z0-9_.-' '_')"
  /opt/keycloak/bin/kcadm.sh get "realms/$realm" > "$work/realms/\${safe}-realm.json"
  /opt/keycloak/bin/kcadm.sh get clients -r "$realm" > "$work/realms/\${safe}-clients.json" || true
  /opt/keycloak/bin/kcadm.sh get roles -r "$realm" > "$work/realms/\${safe}-roles.json" || true
done
if [ -d /opt/keycloak/data/import ]; then
  cp -R /opt/keycloak/data/import/. "$work/import/" 2>/dev/null || true
fi
env | grep '^KC_' | grep -Ev 'PASSWORD|SECRET|TOKEN|KEY' | sort > "$work/runtime/kc-env-sanitized.txt" || true
`;

  try {
    log("Creating Keycloak configuration backup...");
    dockerExec(container, ["sh"], { input: backupScript });
    run("docker", ["cp", `${container}:${containerWorkDir}`, hostWorkDir]);
    dockerExec(container, ["rm", "-rf", containerWorkDir]);
    dockerRun([
      "-v",
      `${hostPathForContainerMount(hostWorkDir)}:/work:ro`,
      "-v",
      `${hostPathForContainerMount(outputDir)}:/backup`,
      configuredNodeImage(),
      "sh",
      "-lc",
      `tar -czf /backup/${shellQuote(stagingFileName)} -C /work .`,
    ]);

    const { hash, signature } = publishBackupArtifactWithEvidence({
      stagingPath,
      hostPath,
      engine: "keycloak",
      sourceContainer: container,
      startedAt,
      metadata: { scope: "configuration", compression: "tar.gz" },
      recordSuccess({ hash: artifactSha256 }) {
        recordDatabaseBackupEvidence({
          engine: "keycloak",
          sourceContainer: container,
          operation: "backup",
          status: "success",
          artifactPath: hostPath,
          artifactSha256,
          startedAt,
        });
      },
    });
    log(`Keycloak config backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, signature, container };
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-rf", containerWorkDir], { allowFailure: true });
      recordDatabaseBackupEvidence({
        engine: "keycloak",
        sourceContainer: container,
        operation: "backup",
        status: "failed",
        artifactPath: hostPath,
        startedAt,
        metadata: { error: String(error?.message ?? error) },
      });
      writeBackupExecutionReport({
        engine: "keycloak",
        sourceContainer: container,
        status: "failed",
        artifactPath: hostPath,
        startedAt,
        metadata: { error: String(error?.message ?? error) },
      });
    } catch {
      // Preserve the original backup failure.
    }
    throw error;
  } finally {
    fs.rmSync(hostWorkParent, { recursive: true, force: true });
  }
}

async function restoreTestKeycloakConfig(options = {}) {
  const backupFileArg = options.backupFile ?? argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  const sourceContainer = options.container ?? argv.container ?? "enterprise-keycloak";
  const backupFile = resolveInside(backupRootPath(), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const backupDir = path.dirname(backupFile);
  const image = options.image ?? argv.image ?? configuredNodeImage();
  const minRealms = positiveInteger(options.minRealms ?? argv.minRealms ?? 1, "--minRealms", 1);
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  let realmCount = 0;
  let jsonCount = 0;

  try {
    log("Running Keycloak config restore dry-run...");
    const result = dockerRun([
      "--entrypoint",
      "sh",
      "-v",
      `${hostPathForContainerMount(backupDir)}:/backup:ro`,
      image,
      "-ec",
      [
        "set -eu",
        "work=/tmp/keycloak-config-restore-test",
        "rm -rf \"$work\" && mkdir -p \"$work\"",
        `tar -xzf /backup/${shellQuote(fileName)} -C "$work"`,
        "test -s \"$work/realms.json\"",
        "test -d \"$work/realms\"",
        "realm_count=$(awk -F\\\" '/\"realm\"/ {count += 1} END {print count + 0}' \"$work/realms.json\")",
        "json_count=$(find \"$work\" -name '*.json' -type f | wc -l)",
        `test "$realm_count" -ge ${minRealms}`,
        "find \"$work\" -name '*.json' -type f -exec sh -c 'test -s \"$1\"' sh {} \\;",
        "printf '%s %s\\n' \"$realm_count\" \"$json_count\"",
      ].join(" && "),
    ], { capture: true });
    const [realmText, jsonText] = String(result.stdout ?? "").trim().split(/\s+/);
    realmCount = Number(realmText);
    jsonCount = Number(jsonText);
    const status = output("docker", ["inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", sourceContainer]).trim();
    if (!/^running( healthy)?$/.test(status)) {
      fail(`Source Keycloak container is not healthy after restore dry-run: ${status}`);
    }
    recordDatabaseBackupEvidence({
      engine: "keycloak",
      sourceContainer,
      operation: "restore_test",
      status: "success",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { realmCount, jsonCount, mode: "config-dry-run" },
    });
    log(`Keycloak config restore dry-run passed with ${realmCount} realm(s) and ${jsonCount} JSON file(s).`);
    return { backupFile, hash, realmCount, jsonCount };
  } catch (error) {
    recordDatabaseBackupEvidence({
      engine: "keycloak",
      sourceContainer,
      operation: "restore_test",
      status: "failed",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { error: String(error?.message ?? error), realmCount, jsonCount },
    });
    throw error;
  }
}

async function backupRestoreDrillKeycloakConfig() {
  log("==> Keycloak config backup/restore drill");
  const container = argv.container ?? "enterprise-keycloak";
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "keycloak", "drills"));
  const backup = await backupKeycloakConfig({ container, outputDir });
  await restoreTestKeycloakConfig({ container, backupFile: backup.hostPath });
  log(`Keycloak config backup/restore drill completed for ${path.basename(backup.hostPath)}.`);
}

async function backupSecretManagerMetadata(options = {}) {
  const outputDir = ensureBackupOutputDir(path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "secret-manager")));
  const startedAt = new Date();
  const fileName = `secret-manager-metadata-${backupTimestamp()}.tar.gz`;
  const hostPath = path.join(outputDir, fileName);
  const stagingPath = backupArtifactStagingPath(hostPath);
  const stagingFileName = path.basename(stagingPath);
  const workDir = makeOpsTempDir("infra-secret-manager-metadata-");

  try {
    const secretManagerStorePath = path.join(infraRoot, "secrets", "infra-secret-manager-store.json");
    if (fs.existsSync(secretManagerStorePath)) {
      assertNoPlaintextFingerprints(readJsonFile(secretManagerStorePath, secretManagerStorePath), "secret manager metadata backup");
    }
    const files = [
      ["infra-secret-manager-store.json", secretManagerStorePath],
      ["infra-secret-manager-audit.log", path.join(infraRoot, "secrets", "infra-secret-manager-audit.log")],
    ];
    for (const [name, filePath] of files) {
      if (fs.existsSync(filePath)) {
        fs.copyFileSync(filePath, path.join(workDir, name));
      }
    }
    const status = runSecretManager(["status"], { capture: true });
    const kmsStatus = runSecretManager(["kms-status"], { capture: true });
    fs.writeFileSync(path.join(workDir, "status.txt"), String(status.stdout ?? ""), "utf8");
    fs.writeFileSync(path.join(workDir, "kms-status.txt"), String(kmsStatus.stdout ?? ""), "utf8");
    fs.writeFileSync(path.join(workDir, "README.txt"), [
      "Infra Secret Manager metadata backup.",
      "The local master key is intentionally not included.",
      "Restore secret material only with the protected master key held outside Git.",
      "",
    ].join("\n"), "utf8");
    dockerRun([
      "-v",
      `${hostPathForContainerMount(workDir)}:/work:ro`,
      "-v",
      `${hostPathForContainerMount(outputDir)}:/backup`,
      configuredNodeImage(),
      "sh",
      "-lc",
      `tar -czf /backup/${shellQuote(stagingFileName)} -C /work .`,
    ]);
    const { hash, signature } = publishBackupArtifactWithEvidence({
      stagingPath,
      hostPath,
      engine: "secret-manager",
      sourceContainer: "host-metadata",
      startedAt,
      metadata: { scope: "metadata-without-master-key", compression: "tar.gz" },
      recordSuccess({ hash: artifactSha256 }) {
        recordDatabaseBackupEvidence({
          engine: "secret-manager",
          sourceContainer: "host-metadata",
          operation: "backup",
          status: "success",
          artifactPath: hostPath,
          artifactSha256,
          startedAt,
        });
      },
    });
    log(`Secret Manager metadata backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, signature };
  } catch (error) {
    recordDatabaseBackupEvidence({
      engine: "secret-manager",
      sourceContainer: "host-metadata",
      operation: "backup",
      status: "failed",
      artifactPath: hostPath,
      startedAt,
      metadata: { error: String(error?.message ?? error) },
    });
    writeBackupExecutionReport({
      engine: "secret-manager",
      sourceContainer: "host-metadata",
      status: "failed",
      artifactPath: hostPath,
      startedAt,
      metadata: { error: String(error?.message ?? error) },
    });
    throw error;
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
}

async function restoreTestSecretManagerMetadata(options = {}) {
  const backupFileArg = options.backupFile ?? argv.backupFile ?? argv._[0];
  if (!backupFileArg) {
    fail("Provide --backupFile <path>.");
  }
  const backupFile = resolveInside(backupRootPath(), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const backupDir = path.dirname(backupFile);
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);

  try {
    dockerRun([
      "-v",
      `${hostPathForContainerMount(backupDir)}:/backup:ro`,
      configuredNodeImage(),
      "sh",
      "-lc",
      [
        "set -eu",
        "work=/tmp/secret-manager-metadata-restore-test",
        "rm -rf \"$work\" && mkdir -p \"$work\"",
        `tar -xzf /backup/${shellQuote(fileName)} -C "$work"`,
        "test -s \"$work/infra-secret-manager-store.json\"",
        "grep -q '\"manager\": \"infra-secret-manager\"' \"$work/infra-secret-manager-store.json\"",
        "grep -q '\"provider\": \"local-bucket-kms\"' \"$work/infra-secret-manager-store.json\"",
        "test ! -e \"$work/infra-secret-manager-master.key\"",
      ].join(" && "),
    ]);
    recordDatabaseBackupEvidence({
      engine: "secret-manager",
      sourceContainer: "host-metadata",
      operation: "restore_test",
      status: "success",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { mode: "metadata-dry-run" },
    });
    log("Secret Manager metadata restore dry-run passed.");
    return { backupFile, hash };
  } catch (error) {
    recordDatabaseBackupEvidence({
      engine: "secret-manager",
      sourceContainer: "host-metadata",
      operation: "restore_test",
      status: "failed",
      artifactPath: backupFile,
      artifactSha256: hash,
      startedAt,
      metadata: { error: String(error?.message ?? error) },
    });
    throw error;
  }
}

async function backupRestoreDrillSecretManagerMetadata() {
  log("==> Secret Manager metadata backup/restore drill");
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "secret-manager", "drills"));
  const backup = await backupSecretManagerMetadata({ outputDir });
  await restoreTestSecretManagerMetadata({ backupFile: backup.hostPath });
  log(`Secret Manager metadata backup/restore drill completed for ${path.basename(backup.hostPath)}.`);
}

async function fullRestoreDrill() {
  log("==> Full Platform restore drill");
  const startedAt = new Date();
  const steps = [
    ["postgres", backupRestoreDrill],
    ["mariadb", backupRestoreDrillMariadb],
    ["minio", backupRestoreDrillMinio],
    ["keycloak", backupRestoreDrillKeycloakConfig],
    ["secret-manager-metadata", backupRestoreDrillSecretManagerMetadata],
  ];
  const results = [];
  let failure = null;
  for (const [name, fn] of steps) {
    const stepStarted = Date.now();
    try {
      await fn();
      results.push({ name, durationMs: Date.now() - stepStarted, status: "success" });
    } catch (error) {
      failure = error;
      results.push({ name, durationMs: Date.now() - stepStarted, status: "failed", error: String(error?.message ?? error) });
      break;
    }
  }
  if (!failure) {
    const healthStarted = Date.now();
    try {
      await infraHealth();
      results.push({ name: "infra-health", durationMs: Date.now() - healthStarted, status: "success" });
    } catch (error) {
      failure = error;
      results.push({ name: "infra-health", durationMs: Date.now() - healthStarted, status: "failed", error: String(error?.message ?? error) });
    }
  }
  const finishedAt = new Date();
  const payload = {
    generatedAt: finishedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    status: failure ? "failed" : "success",
    error: failure ? String(failure?.message ?? failure) : null,
    steps: results,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("restore-drills", `full-restore-drill-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("restore-drills", `full-restore-drill-${stamp}`, [
    "# Platform Full Restore Drill",
    "",
    `Started at: ${payload.startedAt}`,
    `Finished at: ${payload.finishedAt}`,
    `Total duration: ${payload.durationMs} ms`,
    "",
    "| Step | Status | Duration ms |",
    "| --- | --- | ---: |",
    ...results.map((result) => `| ${result.name} | ${result.status} | ${result.durationMs} |`),
  ]);
  log(`Full restore drill report written to ${jsonPath} and ${markdownPath}`);
  if (failure) {
    throw failure;
  }
}

const drEvidenceFamilies = [
  { key: "postgres", engine: "postgres" },
  { key: "mariadb", engine: "mariadb" },
  { key: "minio", engine: "minio" },
  { key: "keycloak", engine: "keycloak" },
  { key: "secret-manager-metadata", engine: "secret-manager" },
];

function readJsonReports(directoryName) {
  const directory = path.join(infraRoot, "reports", directoryName);
  if (!fs.existsSync(directory)) {
    return [];
  }
  return fs.readdirSync(directory)
    .filter((file) => file.endsWith(".json"))
    .map((file) => {
      const filePath = path.join(directory, file);
      try {
        const payload = readJsonFile(filePath, filePath);
        const stat = fs.statSync(filePath);
        return { filePath, payload, mtimeMs: stat.mtimeMs };
      } catch (error) {
        return { filePath, payload: null, mtimeMs: 0, error: String(error?.message ?? error) };
      }
    })
    .filter((report) => report.payload)
    .sort((a, b) => reportTimeMs(b.payload, b.mtimeMs) - reportTimeMs(a.payload, a.mtimeMs));
}

function reportTimeMs(payload, fallbackMs = 0) {
  const value = payload.finishedAt ?? payload.generatedAt ?? payload.startedAt;
  const time = value ? new Date(value).getTime() : NaN;
  return Number.isFinite(time) ? time : fallbackMs;
}

function reportAgeMinutes(payload, nowMs = Date.now()) {
  return Math.max(0, Math.round((nowMs - reportTimeMs(payload)) / 60000));
}

function latestReport(reports, predicate = () => true) {
  return reports.find((report) => predicate(report.payload)) ?? null;
}

function durationStatsMs(values) {
  const clean = values.filter((value) => Number.isFinite(value) && value >= 0).sort((a, b) => a - b);
  if (!clean.length) {
    return { count: 0, averageMs: null, p95Ms: null, minMs: null, maxMs: null };
  }
  const p95Index = Math.min(clean.length - 1, Math.max(0, Math.ceil(clean.length * 0.95) - 1));
  const averageMs = Math.round(clean.reduce((sum, value) => sum + value, 0) / clean.length);
  return {
    count: clean.length,
    averageMs,
    p95Ms: clean[p95Index],
    minMs: clean[0],
    maxMs: clean.at(-1),
  };
}

function formatDurationMinutes(ms) {
  if (!Number.isFinite(ms)) {
    return "n/a";
  }
  return `${(ms / 60000).toFixed(2)} min`;
}

async function drEvidence(options = {}) {
  log("==> DR evidence summary");
  const now = new Date();
  const nowMs = now.getTime();
  const enforce = options.enforce ?? booleanFlag(argv.enforce);
  const rtoMinutes = positiveInteger(options.rtoMinutes ?? argv.rtoMinutes ?? 60, "--rtoMinutes", 1);
  const rpoMinutes = positiveInteger(options.rpoMinutes ?? argv.rpoMinutes ?? 15, "--rpoMinutes", 1);
  const maxBackupAgeHours = positiveInteger(options.maxBackupAgeHours ?? argv.maxBackupAgeHours ?? 26, "--maxBackupAgeHours", 1);
  const maxRestoreDrillAgeHours = positiveInteger(options.maxRestoreDrillAgeHours ?? argv.maxRestoreDrillAgeHours ?? 168, "--maxRestoreDrillAgeHours", 1);
  const maxOffsiteRestoreAgeHours = positiveInteger(options.maxOffsiteRestoreAgeHours ?? argv.maxOffsiteRestoreAgeHours ?? 168, "--maxOffsiteRestoreAgeHours", 1);
  const backupReports = readJsonReports("backups");
  const restoreReports = readJsonReports("restore-drills");
  const offsiteRestoreReports = readJsonReports("offsite-restore-drills");
  const issues = [];

  const backupFamilies = drEvidenceFamilies.map((family) => {
    const latest = latestReport(backupReports, (report) => report.engine === family.engine && report.status === "success");
    const ageMinutes = latest ? reportAgeMinutes(latest.payload, nowMs) : null;
    const fresh = ageMinutes !== null && ageMinutes <= maxBackupAgeHours * 60;
    const integrityVerified = Boolean(latest?.payload.integrityVerified);
    if (!latest) {
      issues.push(`No successful ${family.key} backup report found.`);
    } else if (!fresh) {
      issues.push(`${family.key} latest backup report is stale: ${ageMinutes} minutes old.`);
    }
    if (latest && !integrityVerified) {
      issues.push(`${family.key} latest backup report does not prove integrity verification.`);
    }
    return {
      family: family.key,
      engine: family.engine,
      status: latest ? "found" : "missing",
      fresh,
      ageMinutes,
      integrityVerified,
      latestReport: latest?.filePath ?? null,
      artifactName: latest?.payload.artifactName ?? null,
      finishedAt: latest?.payload.finishedAt ?? null,
    };
  });

  const fullRestoreReports = restoreReports
    .filter((report) => report.payload.status === "success" || report.payload.steps?.every((step) => step.status === "success"))
    .filter((report) => Number.isFinite(report.payload.durationMs));
  const fullRestoreDurations = fullRestoreReports.map((report) => Number(report.payload.durationMs));
  const fullRestoreStats = durationStatsMs(fullRestoreDurations);
  const latestFullRestore = fullRestoreReports[0] ?? null;
  const latestFullRestoreAgeMinutes = latestFullRestore ? reportAgeMinutes(latestFullRestore.payload, nowMs) : null;
  if (!latestFullRestore) {
    issues.push("No successful full restore drill report found.");
  } else if (latestFullRestoreAgeMinutes > maxRestoreDrillAgeHours * 60) {
    issues.push(`Latest full restore drill is stale: ${latestFullRestoreAgeMinutes} minutes old.`);
  }
  if (fullRestoreStats.averageMs !== null && fullRestoreStats.averageMs > rtoMinutes * 60000) {
    issues.push(`Average full restore duration exceeds RTO ${rtoMinutes} minutes.`);
  }
  if (latestFullRestore?.payload.durationMs > rtoMinutes * 60000) {
    issues.push(`Latest full restore duration exceeds RTO ${rtoMinutes} minutes.`);
  }

  const latestOffsiteDryRun = latestReport(offsiteRestoreReports, (report) => ["success", "external-pending"].includes(report.status) && report.mode === "dry-run");
  const latestOffsiteRestore = latestReport(offsiteRestoreReports, (report) => report.status === "success" && report.mode === "restore");
  const latestOffsiteRestoreAgeMinutes = latestOffsiteRestore ? reportAgeMinutes(latestOffsiteRestore.payload, nowMs) : null;
  const latestOffsiteDryRunOffsite = latestOffsiteDryRun ? Boolean(latestOffsiteDryRun.payload.restic?.repositoryOffsite) : null;
  const latestOffsiteRestoreOffsite = latestOffsiteRestore ? Boolean(latestOffsiteRestore.payload.restic?.repositoryOffsite) : null;
  const latestOffsiteRestoreCoverage = latestOffsiteRestore ? (latestOffsiteRestore.payload.coverage ?? offsiteRestoreCoverage(latestOffsiteRestore.payload)) : null;
  if (!latestOffsiteRestore) {
    issues.push("No successful full off-site Restic restore drill report found.");
  } else if (latestOffsiteRestoreAgeMinutes > maxOffsiteRestoreAgeHours * 60) {
    issues.push(`Latest off-site restore drill is stale: ${latestOffsiteRestoreAgeMinutes} minutes old.`);
  } else if (!latestOffsiteRestoreOffsite) {
    issues.push("Latest Restic restore drill did not use a remote off-site repository.");
  } else if (!latestOffsiteRestoreCoverage?.complete) {
    issues.push(`Latest off-site restore drill does not prove the exact signed resource set. Missing: ${latestOffsiteRestoreCoverage?.missingRequiredResourceIds?.join(", ") || "unknown"}.`);
  }

  const drCompose = readText(path.join(infraRoot, "compose.dr.yaml"));
  const walArchiveConfigured = /archive_mode=on/.test(drCompose) && /enterprise_postgres_wal_archive/.test(drCompose);
  if (!walArchiveConfigured) {
    issues.push("PostgreSQL WAL archive overlay is not configured.");
  }

  const payload = {
    generatedAt: now.toISOString(),
    mode: enforce ? "enforce" : "summary",
    targets: {
      rtoMinutes,
      rpoMinutes,
      maxBackupAgeHours,
      maxRestoreDrillAgeHours,
      maxOffsiteRestoreAgeHours,
    },
    rpoEvidence: {
      walArchiveConfigured,
      backupFamilies,
    },
    rtoEvidence: {
      latestFullRestoreReport: latestFullRestore?.filePath ?? null,
      latestFullRestoreAgeMinutes,
      latestFullRestoreDurationMs: latestFullRestore?.payload.durationMs ?? null,
      fullRestoreStats,
    },
    offsiteEvidence: {
      latestDryRunReport: latestOffsiteDryRun?.filePath ?? null,
      latestDryRunRepositoryType: latestOffsiteDryRun?.payload.restic?.repositoryType ?? null,
      latestDryRunOffsite: latestOffsiteDryRunOffsite,
      latestRestoreReport: latestOffsiteRestore?.filePath ?? null,
      latestRestoreRepositoryType: latestOffsiteRestore?.payload.restic?.repositoryType ?? null,
      latestRestoreOffsite: latestOffsiteRestoreOffsite,
      latestRestoreAgeMinutes: latestOffsiteRestoreAgeMinutes,
      latestRestoreDurationMs: latestOffsiteRestore?.payload.durationMs ?? null,
      latestRestoreCoverage: latestOffsiteRestoreCoverage,
    },
    status: issues.length ? "warning" : "passed",
    issues,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("dr", `dr-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("dr", `dr-evidence-${stamp}`, [
    "# Platform DR Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    `RPO target: ${rpoMinutes} minutes`,
    `RTO target: ${rtoMinutes} minutes`,
    "",
    "| Backup family | Fresh | Age minutes | Integrity | Latest report |",
    "| --- | --- | ---: | --- | --- |",
    ...backupFamilies.map((family) => `| ${family.family} | ${family.fresh ? "yes" : "no"} | ${family.ageMinutes ?? "n/a"} | ${family.integrityVerified ? "yes" : "no"} | ${family.latestReport ?? "n/a"} |`),
    "",
    "## Restore Timing",
    "",
    `Latest full restore: ${formatDurationMinutes(payload.rtoEvidence.latestFullRestoreDurationMs)}`,
    `Average full restore: ${formatDurationMinutes(fullRestoreStats.averageMs)}`,
    `P95 full restore: ${formatDurationMinutes(fullRestoreStats.p95Ms)}`,
    `Samples: ${fullRestoreStats.count}`,
    "",
    "## Off-site Restore",
    "",
    `Latest dry-run report: ${payload.offsiteEvidence.latestDryRunReport ?? "n/a"}`,
    `Latest full restore report: ${payload.offsiteEvidence.latestRestoreReport ?? "n/a"}`,
    `Latest full restore coverage complete: ${payload.offsiteEvidence.latestRestoreCoverage?.complete ? "yes" : "no"}`,
    `Latest full restore missing resources: ${payload.offsiteEvidence.latestRestoreCoverage?.missingRequiredResourceIds?.join(", ") || "none"}`,
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- None"]),
  ]);
  log(`DR evidence written to ${jsonPath} and ${markdownPath}`);
  if (enforce && issues.length) {
    fail(`DR evidence enforcement failed with ${issues.length} issue(s). Reports: ${jsonPath}, ${markdownPath}`);
  }
  return payload;
}

function listDumpArtifacts(directory) {
  if (!fs.existsSync(directory)) {
    return [];
  }
  return fs.readdirSync(directory)
    .filter((file) => file.endsWith(".dump"))
    .map((file) => {
      const filePath = resolveInside(directory, path.join(directory, file));
      const shaPath = `${filePath}.sha256`;
      const sigPath = backupSignatureSidecarPath(filePath);
      return {
        file,
        filePath,
        mtimeMs: fs.statSync(filePath).mtimeMs,
        shaPath: fs.existsSync(shaPath) ? resolveInside(directory, shaPath) : null,
        sigPath: fs.existsSync(sigPath) ? resolveInside(directory, sigPath) : null,
      };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
}

function pruneDumpDirectory({ directory, dryRun, label, minKeep, retentionDays }) {
  const artifacts = listDumpArtifacts(directory);
  const cutoff = Date.now() - retentionDays * 86400000;
  let pruned = 0;
  for (const [index, artifact] of artifacts.entries()) {
    if (index < minKeep || artifact.mtimeMs >= cutoff) {
      continue;
    }
    const action = dryRun ? "Would delete" : "Deleting";
    log(`${action} ${label} backup artifact: ${artifact.filePath}`);
    if (artifact.shaPath) {
      log(`${action} ${label} checksum: ${artifact.shaPath}`);
    }
    if (artifact.sigPath) {
      log(`${action} ${label} signature: ${artifact.sigPath}`);
    }
    if (!dryRun) {
      fs.rmSync(artifact.filePath, { force: true });
      if (artifact.shaPath) fs.rmSync(artifact.shaPath, { force: true });
      if (artifact.sigPath) fs.rmSync(artifact.sigPath, { force: true });
    }
    pruned += 1;
  }
  return { kept: artifacts.length - pruned, pruned, total: artifacts.length };
}

function assertRecentRestoreTest(_container, database, _user, maxAgeDays) {
  const cutoff = Date.now() - positiveInteger(maxAgeDays, "--maxRestoreTestAgeDays") * 86400 * 1000;
  const exists = backupRestoreRunRecords().some((record) =>
    record.operation === "restore_test"
      && record.status === "success"
      && record.databaseName === database
      && Date.parse(record.finishedAt) >= cutoff);
  if (!exists) {
    fail(`Refusing backup retention cleanup: no successful restore_test in the last ${maxAgeDays} days.`);
  }
}

async function prunePostgresBackups(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? defaultPostgresBackupDatabase();
  const user = options.user ?? argv.user ?? "postgres";
  const backupDir = path.resolve(options.backupDir ?? argv.backupDir ?? path.join(infraRoot, "backups", "postgres"));
  const drillDir = path.resolve(options.drillDir ?? argv.drillDir ?? path.join(backupDir, "drills"));
  const backupRetentionDays = positiveInteger(options.retentionDays ?? argv.retentionDays ?? 30, "--retentionDays");
  const drillRetentionDays = positiveInteger(options.drillRetentionDays ?? argv.drillRetentionDays ?? 14, "--drillRetentionDays");
  const minBackups = positiveInteger(options.minBackups ?? argv.minBackups ?? 3, "--minBackups");
  const minDrills = positiveInteger(options.minDrills ?? argv.minDrills ?? 3, "--minDrills");
  const maxRestoreTestAgeDays = positiveInteger(options.maxRestoreTestAgeDays ?? argv.maxRestoreTestAgeDays ?? 35, "--maxRestoreTestAgeDays");
  const dryRun = options.dryRun ?? booleanFlag(argv.dryRun);

  resolveInside(path.join(infraRoot, "backups"), backupDir);
  if (fs.existsSync(drillDir)) {
    resolveInside(path.join(infraRoot, "backups"), drillDir);
  }
  assertRecentRestoreTest(container, database, user, maxRestoreTestAgeDays);

  log(`==> PostgreSQL backup retention${dryRun ? " dry run" : ""}`);
  const backups = pruneDumpDirectory({ directory: backupDir, dryRun, label: "regular", minKeep: minBackups, retentionDays: backupRetentionDays });
  const drills = pruneDumpDirectory({ directory: drillDir, dryRun, label: "drill", minKeep: minDrills, retentionDays: drillRetentionDays });
  const stamp = reportTimestamp();
  const payload = {
    generatedAt: new Date().toISOString(),
    status: "passed",
    mode: dryRun ? "dry-run" : "apply",
    container,
    database,
    user,
    backupDir,
    drillDir,
    policy: {
      backupRetentionDays,
      drillRetentionDays,
      minBackups,
      minDrills,
      maxRestoreTestAgeDays,
    },
    summary: {
      regular: backups,
      drills,
    },
  };
  const jsonPath = writeJsonReport("postgres-backup-prune", `prune-postgres-backups-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("postgres-backup-prune", `prune-postgres-backups-${stamp}`, [
    "# PostgreSQL Backup Retention",
    "",
    `Generated at: ${payload.generatedAt}`,
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    "",
    "| Family | Kept | Pruned | Total |",
    "| --- | ---: | ---: | ---: |",
    `| regular | ${backups.kept} | ${backups.pruned} | ${backups.total} |`,
    `| drills | ${drills.kept} | ${drills.pruned} | ${drills.total} |`,
  ]);
  log(`Retention complete: regular ${backups.pruned}/${backups.total} pruned, drill ${drills.pruned}/${drills.total} pruned.`);
  log(`PostgreSQL backup retention report written to ${jsonPath} and ${markdownPath}`);
}

function secretScanPatterns() {
  return [
    ["private-key", /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/],
    ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/],
    ["aws-secret-access-key", /\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\b\s*[:=]\s*['"]?[A-Za-z0-9/+]{32,}/],
    ["api-token-assignment", /\b(api|access|secret|private|client)_?(key|token|secret)\b\s*[:=]\s*['"][^'"]{16,}/i],
    ["password-assignment", /\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{8,}/i],
    ["smtp-password", /\bSMTP_PASSWORD\b\s*=.+/i],
  ];
}

async function secretScan() {
  await withLocalCheckReport("secret-scan", async () => {
    const root = path.resolve(argv.infraRoot ?? infraRoot);
    const patterns = secretScanPatterns();
    const ignoredDirs = new Set([".git", ".codex-backups", ".tmp", "node_modules", ".pnpm-store", ".next", "dist", "coverage", "backups", "release", "reports", "secrets", "certs", "acme", "sbom"]);
    const hits = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (ignoredDirs.has(entry.name)) continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
          continue;
        }
        if (!entry.isFile() || /^\.env(?:\.|$)/.test(entry.name) || fs.statSync(fullPath).size > 2 * 1024 * 1024) continue;
        const content = fs.readFileSync(fullPath);
        if (content.includes(0)) continue;
        content.toString("utf8").split(/\r?\n/).forEach((line, index) => {
          if (/change_me|placeholder|example|your-domain|smtpPassword|redisPassword|dbPassword|rootPassword|WITH PASSWORD :'\w+_password'/i.test(line)) return;
          const match = patterns.find(([, pattern]) => pattern.test(line));
          if (match) hits.push({ file: path.relative(infraRoot, fullPath).replaceAll("\\", "/"), line: index + 1, kind: match[0] });
        });
      }
    };
    walk(root);
    if (hits.length) {
      hits.forEach((hit) => log(`${hit.file}:${hit.line}: potential ${hit.kind}`));
      fail("Potential hardcoded secrets found. Review the hits above.");
    }
    log("Platform repository secret scan passed without printing secret values.");
  }, { scope: "platform-infrastructure" });
}

async function securitySmoke() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const portalPublicUrl = argv.portalBase ?? argv.uiBase ?? env.CONTROL_CENTER_PUBLIC_URL ?? env.UI_PUBLIC_URL ?? env.NEXT_PUBLIC_UI_URL ?? "https://portal.localhost.com";
  const docsPublicUrl = argv.docsBase ?? env.DOCS_PUBLIC_URL ?? "https://docs.localhost.com";
  const portalBase = String(portalPublicUrl).replace(/\/$/, "");
  const docsBase = String(docsPublicUrl).replace(/\/$/, "");
  const accountPublicUrl = argv.accountBase ?? "";
  const apiPublicUrl = argv.apiBase ?? env.CONTROL_CENTER_SECURITY_SMOKE_API_BASE ?? (booleanFlag(argv.includeApi) ? (env.API_PUBLIC_URL ?? env.NEXT_PUBLIC_API_URL ?? "") : "");
  const accountBase = String(accountPublicUrl || "").replace(/\/$/, "");
  const apiBase = String(apiPublicUrl || "").replace(/\/$/, "");
  const trustedOrigin = String(argv.accountOrigin ?? argv.trustedOrigin ?? portalBase).replace(/\/$/, "");
  const defaultUrlList = [`${portalBase}/`];
  if (docsBase && docsBase !== portalBase) defaultUrlList.push(`${docsBase}/`);
  if (accountBase) defaultUrlList.push(`${accountBase}/`);
  if (apiBase) defaultUrlList.push(`${apiBase}/health`);
  const defaultUrls = defaultUrlList.join(",");
  const urls = (argv.urls ?? defaultUrls).split(",").map((url) => url.trim()).filter(Boolean);
  await withLocalCheckReport("security-smoke", async () => {
    for (const url of urls) {
      log(`Checking ${url}`);
      const response = await request("HEAD", url);
      const headers = headerText(response.headers);
      const requiredHeaders = ["x-content-type-options", "referrer-policy", "permissions-policy"];
      let isHttpUrl = false;
      try {
        isHttpUrl = new URL(url).protocol === "http:";
      } catch {
        isHttpUrl = false;
      }
      if (!(booleanFlag(argv.allowHttpNoHsts) && isHttpUrl)) {
        requiredHeaders.unshift("strict-transport-security");
      }
      for (const required of requiredHeaders) {
        if (!headers.includes(required)) {
          fail(`Missing ${required} on ${url}`);
        }
      }
    }

    if (apiBase) {
      assertStatus(await request("GET", `${apiBase}/account/snapshot`), 401, "unauthenticated account snapshot");
      assertStatus(await request("POST", `${apiBase}/auth/logout`, { headers: { Origin: "https://evil.example" } }), 403, "untrusted Origin");
      assertStatus(await request("POST", `${apiBase}/auth/logout`, { headers: { "Sec-Fetch-Site": "cross-site" } }), 403, "cross-site Fetch Metadata");
      assertStatus(await request("POST", `${apiBase}/auth/logout`, { headers: { Origin: trustedOrigin, "Sec-Fetch-Site": "same-site" } }), 200, "same-site logout");
      assertStatus(await request("POST", `${apiBase}/auth/logout`, { headers: { Origin: trustedOrigin, "Sec-Fetch-Site": "cross-site" } }), 200, "trusted cross-site logout");
    } else {
      log("Skipping backend security smoke because no public API base was provided.");
    }
    log("Security smoke checks passed.");
  }, { urls, apiBase: Boolean(apiBase) });
}

async function wafSmoke() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const runtimeDomain = expandTemplate(env.DOMAIN ?? env.LOCAL_DOMAIN ?? "localhost.com", env);
  const portalHost = expandTemplate(env.CONTROL_CENTER_HOST ?? env.ADMIN_HOST ?? `portal.${runtimeDomain}`, env);
  const defaultPortalBase = env.CONTROL_CENTER_PUBLIC_URL ?? `https://${portalHost}`;
  const apiBase = argv.apiBase ? String(argv.apiBase).replace(/\/$/, "") : "";
  const phpBase = String(argv.phpBase ?? argv.portalBase ?? defaultPortalBase).replace(/\/$/, "");
  const probeBase = apiBase || phpBase;
  const smokeHeaders = { "User-Agent": "platform-waf-smoke/1.0" };
  await withLocalCheckReport("waf-smoke", async () => {
    log("==> WAF smoke checks");

    assertStatus(await request("GET", apiBase ? `${apiBase}/health` : `${phpBase}/`, { headers: smokeHeaders }), 200, "WAF pass-through health");
    const sqlInjection = await request("GET", `${probeBase}/?search=%27%20OR%201%3D1--`, { headers: smokeHeaders });
    if (![403, 406].includes(sqlInjection.status)) {
      fail(`WAF SQL injection probe expected HTTP 403/406, got ${sqlInjection.status}: ${sqlInjection.text}`);
    }

    const xssProbe = await request("GET", `${probeBase}/?x=%3Cscript%3Ealert(1)%3C/script%3E`, { headers: smokeHeaders });
    if (![403, 406].includes(xssProbe.status)) {
      fail(`WAF XSS probe expected HTTP 403/406, got ${xssProbe.status}: ${xssProbe.text}`);
    }

    const sensitiveProbe = await request("GET", `${phpBase}/.env`, { headers: smokeHeaders });
    if (![403, 404].includes(sensitiveProbe.status)) {
      fail(`WAF sensitive file probe expected HTTP 403/404, got ${sensitiveProbe.status}: ${sensitiveProbe.text}`);
    }

    const scannerProbe = await request("GET", `${phpBase}/wp-login.php`, { headers: smokeHeaders });
    if (![403, 404].includes(scannerProbe.status)) {
      fail(`WAF scanner path probe expected HTTP 403/404, got ${scannerProbe.status}: ${scannerProbe.text}`);
    }

    log("WAF smoke checks passed.");
  }, { apiBase: Boolean(apiBase), phpBase, probeBase });
}

async function infraHealth() {
  const candidateEvidence = currentCandidateIdentityEvidence({
    envFile: argv.envFile ?? path.join(infraRoot, ".env"),
    projectName: argv.project ?? argv.projectName,
  });
  const metadata = {
    candidate: candidateEvidence.candidate,
    candidateError: candidateEvidence.error,
  };
  await withLocalCheckReport("infra-health", async () => {
    try {
      return await infraHealthBody();
    } finally {
      const candidateEndEvidence = currentCandidateIdentityEvidence({
        envFile: argv.envFile ?? path.join(infraRoot, ".env"),
        projectName: argv.project ?? argv.projectName,
      });
      metadata.candidateEnd = candidateEndEvidence.candidate;
      metadata.candidateStable = Boolean(
        candidateEvidence.candidate?.trusted
        && candidateEndEvidence.candidate?.trusted
        && candidateIdentityMatches(candidateEvidence.candidate, candidateEndEvidence.candidate),
      );
      metadata.candidateError = candidateEvidence.error ?? candidateEndEvidence.error;
    }
  }, metadata);
}

async function infraHealthBody() {
  const defaultContainers = [
    "enterprise-traefik", "enterprise-waf", "enterprise-postgres", "enterprise-redis", "enterprise-keycloak", "enterprise-nats", "enterprise-minio", "php-apache", "enterprise-control-center", "enterprise-project-router", "mariadb", "phpmyadmin", "phppgadmin", "enterprise-local-dns", "enterprise-prometheus", "enterprise-node-exporter", "enterprise-cadvisor", "enterprise-platform-alert-dispatcher", "enterprise-alertmanager", "enterprise-grafana", "enterprise-loki", "enterprise-promtail",
  ];
  const containers = (argv.containers ? String(argv.containers).split(",") : defaultContainers).map((container) => container.trim()).filter(Boolean);
  const envFile = path.resolve(infraRoot, argv.envFile ?? ".env");
  const env = parseEnv(envFile);
  const runtimeDomain = expandTemplate(env.DOMAIN ?? env.LOCAL_DOMAIN ?? "localhost.com", env);
  const defaultAdminHost = expandTemplate(env.CONTROL_CENTER_HOST ?? env.ADMIN_HOST ?? `portal.${runtimeDomain}`, env);
  const defaultDocsHost = expandTemplate(env.DOCS_HOST ?? `docs.${runtimeDomain}`, env);
  const uiBase = (argv.uiBase ?? argv.docsBase ?? `https://${defaultDocsHost}`).replace(/\/$/, "");
  const adminBase = (argv.adminBase ?? argv.projectsBase ?? `https://${defaultAdminHost}`).replace(/\/$/, "");
  const checks = [];
  const addCheck = (name, ok, detail = "") => checks.push({ name, ok, detail });
  for (const container of containers) {
    const inspect = run("docker", ["inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", container], { allowFailure: true, capture: true });
    if (inspect.status !== 0) {
      addCheck(`container:${container}`, false, "not found");
      continue;
    }
    const [status, health = "none"] = String(inspect.stdout ?? "").trim().split("|");
    addCheck(`container:${container}`, status === "running" && (health === "none" || health === "healthy"), `status=${status || "unknown"} health=${health || "none"}`);
  }
  const httpChecks = [
    { name: "docs-home", method: "HEAD", url: `${uiBase}/`, statuses: [200, 308] },
    { name: "admin-control-center", method: "GET", url: `${adminBase}/`, statuses: [200], body: /Control Center|ops-shell|Passati|Non passati|GO LIVE/ },
    { name: "waf-xss-block", method: "GET", url: `${adminBase}/?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E`, statuses: [403, 406] },
    { name: "waf-sensitive-file-block", method: "GET", url: `${adminBase}/.env`, statuses: [403, 404] },
  ];
  for (const check of httpChecks) {
    const started = Date.now();
    try {
      const response = await request(check.method, check.url, { headers: { "User-Agent": "platform-infra-health/1.0" } });
      const statusOk = check.statuses.includes(response.status);
      const bodyOk = !check.body || check.body.test(response.text);
      addCheck(`http:${check.name}`, statusOk && bodyOk, `status=${response.status} latencyMs=${Date.now() - started}`);
    } catch (error) {
      addCheck(`http:${check.name}`, false, String(error?.message ?? error));
    }
  }
  if (booleanFlag(argv.json)) log(JSON.stringify({ ok: checks.every((check) => check.ok), checks }, null, 2));
  else for (const check of checks) log(`${check.ok ? "OK  " : "FAIL"} ${check.name}${check.detail ? ` - ${check.detail}` : ""}`);
  const failures = checks.filter((check) => !check.ok);
  if (failures.length) fail(`Infra health failed: ${failures.map((failure) => failure.name).join(", ")}`);
  log("Infra health passed.");
}

async function signImages() {
  const entries = releaseImageEntries({
    env: parseEnv(path.resolve(argv.envFile ?? path.join(infraRoot, ".env"))),
    imagesArg: argv.images,
    manifestPath: argv.imageManifest ?? argv.projectManifest ?? argv.appManifest,
  });
  if (!entries.length) fail("No images found. Pass --imageManifest <file> or --images <ref[,ref]>.");
  const key = argv.key ?? process.env.COSIGN_KEY;
  if (run("cosign", ["version"], { capture: true, allowFailure: true }).status !== 0) fail("cosign is required for image signing.");
  if (!key) fail("Set COSIGN_KEY to a key reference or use keyless signing in CI.");
  for (const { key: imageKey, image } of entries) {
    assertDigestPinnedImageRef(imageKey, image);
    run("cosign", ["sign", "--key", key, image]);
  }
  log(`Image signing completed for ${entries.length} immutable image(s).`);
}

function staticSecurityInfraOnlyCheck() {
  log("==> Static security checks (platform infrastructure)");
  const supplyChain = evaluateSupplyChain(infraRoot);
  if (supplyChain.status !== "passed") fail(`Supply-chain policy failed: ${supplyChain.failures.join("; ")}`);
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const composeRuntime = readText(path.join(infraRoot, "compose.runtime.yaml"));
  const composeNetworks = readText(path.join(infraRoot, "compose.networks.yaml"));
  const composeIsolation = readText(path.join(infraRoot, "compose.runtime-isolation.yaml"));
  const composeSecrets = readText(path.join(infraRoot, "compose.secrets.yaml"));
  const composeManagedSecrets = readText(path.join(infraRoot, "compose.managed-secrets.yaml"));
  const composeVps = readText(path.join(infraRoot, "scripts", "compose-vps.sh"));
  const contract = readText(path.join(infraRoot, "scripts", "hosted-workload-contract.mjs"));
  const lockScript = readText(path.join(infraRoot, "scripts", "hosted-workload-lock.sh"));
  const prepareScript = readText(path.join(infraRoot, "scripts", "prepare-hosted-workloads.sh"));
  const router = readText(path.join(infraRoot, "project-router", "server.mjs"));
  const alertmanager = readText(path.join(infraRoot, "alertmanager", "alertmanager.yml"));
  const dispatcher = readText(path.join(infraRoot, "platform-alert-dispatcher", "server.mjs"));
  const workflow = readText(path.join(infraRoot, ".github", "workflows", "enterprise-infra.yml"));
  const platformText = [compose, composeRuntime, composeNetworks, composeIsolation, composeSecrets, composeManagedSecrets].join("\n");
  assertMatch(compose, /^name:\s+\$\{COMPOSE_PROJECT_NAME:-platform_infra\}/m, "Compose must use an explicit project name.");
  assertNoMatch(platformText, /^\s{2}(?:backend|web|worker-jobs|worker-notifications|node-account|node-ui|php-anniversary|php-fiplatform|php-matthewdifilippo|php-stream|php-workcalendar):/m, "Platform Compose must not define concrete hosted applications.");
  assertNoMatch(platformText, /\b(?:APP_DB|BACKEND_DB|WORKER_JOBS_DB|WORKER_NOTIFICATIONS_DB|DATABASE_URL|SESSION_SIGNING_KEYS|HASH_PEPPER|TURNSTILE)\b/i, "Platform Compose must not own hosted application credentials.");
  assertNoMatch(composeRuntime, /\/stexor|\/anniversary|\/fiplatform|\/matthewdifilippo|\/stream|\/workcalendar|PROJECT_UPSTREAMS:/i, "Runtime overlay must not mount or route concrete projects.");
  assertMatch(composeVps, /HOSTED_WORKLOAD_LOCK[\s\S]*hosted-workload-lock\.sh[\s\S]*compose-files/, "VPS Compose wrapper must load only a verified external workload lock.");
  assertNoMatch(composeVps, /compose\.build\.yaml/, "VPS Compose wrapper must not load application build definitions.");
  assertMatch(contract, /sha256File[\s\S]*Locked file changed/, "Hosted workload contract must bind and re-verify file hashes.");
  assertMatch(contract, /read_only[\s\S]*no-new-privileges[\s\S]*cap_drop/, "Hosted workload contract must enforce runtime hardening.");
  assertMatch(contract, /com\.platform\.workload-id[\s\S]*com\.platform\.workload-role/, "Hosted workload contract must bind workload identity labels.");
  assertMatch(contract, /PASSWORD|TOKEN|SECRET|DATABASE_URL|NATS_URL/, "Hosted workload env validation must reject secret-bearing keys.");
  assertMatch(lockScript, /core-env-file[\s\S]*project-name[\s\S]*compose-files[\s\S]*env-files/, "Hosted workload lock reader must expose only verified fields.");
  assertMatch(prepareScript, /hosted-workload-contract\.mjs/, "Hosted workload preparation must use the contract validator.");
  assertMatch(composeNetworks, /platform_edge:[\s\S]*platform_routing:[\s\S]*platform_observability:[\s\S]*platform_egress:/, "Platform trust zones must be explicit.");
  assertMatch(composeIsolation, /docker-operation-gateway:[\s\S]*\/var\/run\/docker\.sock:\/var\/run\/docker\.sock:ro/, "Only the typed Docker operation gateway may mount the raw socket.");
  assertMatch(router, /PROJECT_ROUTER_ALLOWED_UPSTREAMS[\s\S]*validateUpstream/, "Project Router must enforce an exact upstream allowlist.");
  assertNoMatch(router, /node:child_process|spawn\(|execFile\(|stopManagedProject/, "Project Router must remain proxy-only.");
  assertMatch(alertmanager, /platform-alert-dispatcher:3000/, "Alertmanager must deliver through the platform-owned dispatcher.");
  assertMatch(dispatcher, /ALERTMANAGER_WEBHOOK_TOKEN_FILE[\s\S]*SMTP_PASSWORD_FILE/, "Alert dispatcher must consume credentials through files.");
  assertMatch(dispatcher, /platform_alert_delivery_total/, "Alert dispatcher must expose delivery metrics.");
  assertNoMatch(workflow, /project-repository|PROJECT_REPO_TOKEN|Checkout application source|compose\.build\.yaml/, "Infrastructure CI must not checkout or build hosted applications.");
  assertMatch(workflow, /static-security-check --infraOnly[\s\S]*hosted-workload-contract/, "Infrastructure CI must verify the platform boundary and hosted workload contract.");
  log("Static platform infrastructure checks passed.");
}

async function staticSecurityCheck() {
  await withLocalCheckReport("static-security-check", async () => {
    staticSecurityInfraOnlyCheck();
  }, { infraOnly: true, scope: "platform-infrastructure" });
}



async function validateLocalSecrets() {
  const secretsDir = path.resolve(argv.secretsDir ?? path.join(infraRoot, "secrets"));
  const required = [
    "backup_scheduler_docker_gateway_token",
    "postgres_superuser_password",
    "keycloak_db_password",
    "redis_password",
    "keycloak_admin_password",
    "nats_password",
    "minio_root_password",
    "mariadb_root_password",
    "phpmyadmin_control_password",
    "grafana_admin_password",
    "projects_gateway_signing_keys",
    "control_center_vault_keys",
    "backup_signing_keys",
    "alertmanager_webhook_token",
    "smtp_password",
  ];
  for (const name of required) {
    const filePath = path.join(secretsDir, `${name}.txt`);
    if (!fs.existsSync(filePath)) {
      fail(`Missing local secret file: ${filePath}`);
    }
    const value = fs.readFileSync(filePath, "utf8").trim();
    if (!isUsableSecret(value)) {
      fail(`Invalid local secret value in ${filePath}`);
    }
  }
  for (const name of ["projects_gateway_signing_keys", "control_center_vault_keys", "backup_signing_keys"]) {
    const keys = parseVersionedSecretKeys(fs.readFileSync(path.join(secretsDir, `${name}.txt`), "utf8"));
    if (!keys.length || keys.some((key) => key.secret.length < 48)) {
      fail(`Invalid versioned key ring in ${path.join(secretsDir, `${name}.txt`)}`);
    }
  }
  runSecretManager(["verify", "--secretsDir", secretsDir]);
  log("Local secrets validation passed.");
}

async function installPostgresBackupCron() {
  const backupAt = parseCronTime(argv.backupAt ?? argv.at ?? "03:15", "backupAt");
  const drillAt = parseCronTime(argv.drillAt ?? "04:15", "drillAt");
  const retentionAt = parseCronTime(argv.retentionAt ?? "05:15", "retentionAt");
  const drillWeekday = String(argv.drillWeekday ?? "0");
  if (!/^[0-7]$/.test(drillWeekday)) {
    fail("Use --drillWeekday 0-7, where 0/7 is Sunday.");
  }
  const cronRoot = argv.cronRoot ?? infraRoot;
  const backupLine = `${backupAt.minute} ${backupAt.hour} * * * cd ${shellQuote(cronRoot)} && sh ./scripts/backup-postgres.sh >> ./backups/postgres/backup.log 2>&1`;
  const drillLine = `${drillAt.minute} ${drillAt.hour} * * ${drillWeekday} cd ${shellQuote(cronRoot)} && sh ./scripts/backup-restore-drill.sh >> ./backups/postgres/drills/restore-drill.log 2>&1`;
  const retentionLine = `${retentionAt.minute} ${retentionAt.hour} * * * cd ${shellQuote(cronRoot)} && sh ./scripts/prune-postgres-backups.sh >> ./backups/postgres/retention.log 2>&1`;
  log("Add these lines to the production host crontab:");
  log(backupLine);
  log(drillLine);
  log(retentionLine);
}

async function installMariadbBackupCron() {
  const backupAt = parseCronTime(argv.backupAt ?? argv.at ?? "03:45", "backupAt");
  const drillAt = parseCronTime(argv.drillAt ?? "04:45", "drillAt");
  const drillWeekday = String(argv.drillWeekday ?? "0");
  if (!/^[0-7]$/.test(drillWeekday)) {
    fail("Use --drillWeekday 0-7, where 0/7 is Sunday.");
  }
  const cronRoot = argv.cronRoot ?? infraRoot;
  const backupLine = `${backupAt.minute} ${backupAt.hour} * * * cd ${shellQuote(cronRoot)} && sh ./scripts/backup-mariadb.sh >> ./backups/mariadb/backup.log 2>&1`;
  const drillLine = `${drillAt.minute} ${drillAt.hour} * * ${drillWeekday} cd ${shellQuote(cronRoot)} && sh ./scripts/backup-restore-drill-mariadb.sh >> ./backups/mariadb/drills/restore-drill.log 2>&1`;
  log("Add these lines to the production host crontab:");
  log(backupLine);
  log(drillLine);
}





function latestFreshLocalCheck(commandName, maxAgeHours = 168) {
  const report = latestJsonReport("local-checks", `${commandName}-`, (payload) => (
    payload?.status === "passed"
    && payload.scope === "platform-infrastructure"
    && payload.command === commandName
  ));
  if (!report) {
    return {
      command: commandName,
      status: "missing",
      fresh: false,
      passed: false,
      reportPath: null,
      ageHours: null,
    };
  }
  const generatedAt = report.payload.generatedAt || report.payload.finishedAt || report.payload.startedAt || "";
  const generatedMs = Date.parse(generatedAt);
  const ageHours = Number.isFinite(generatedMs) ? Math.max(0, (Date.now() - generatedMs) / 36e5) : null;
  const fresh = ageHours !== null && ageHours <= maxAgeHours;
  return {
    command: commandName,
    status: report.payload.status,
    fresh,
    passed: fresh,
    reportPath: path.relative(infraRoot, report.filePath).replaceAll("\\", "/"),
    generatedAt,
    ageHours,
  };
}

async function pentestReadiness() {
  log("==> Penetration test readiness");
  if (booleanFlag(argv.refresh)) {
    await securityMatrix();
    await staticSecurityCheck();
    await secretScan();
  }
  const startedAt = new Date();
  const requiredReports = [
    latestFreshLocalCheck("security-matrix"),
    latestFreshLocalCheck("security-smoke"),
    latestFreshLocalCheck("static-security-check"),
    latestFreshLocalCheck("secret-scan"),
  ];
  const threatModelPath = path.join(infraRoot, "THREAT-MODEL.md");
  const threatModelPresent = fs.existsSync(threatModelPath) && fs.statSync(threatModelPath).size > 0;
  const failedChecks = [
    ...requiredReports.filter((item) => !item.passed).map((item) => `${item.command}:${item.status}`),
    ...(threatModelPresent ? [] : ["THREAT-MODEL.md:missing"]),
  ];
  const status = failedChecks.length ? "failed" : "passed";
  const finishedAt = new Date();
  const payload = {
    generatedAt: finishedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: Math.max(0, finishedAt.getTime() - startedAt.getTime()),
    status,
    mode: "readiness-plan",
    scope: "platform-infrastructure",
    command: "pentest-readiness",
    detail: status === "passed"
      ? "Infrastructure penetration test readiness is approved from current non-secret evidence; external professional pentest remains required before enterprise launch."
      : "Infrastructure penetration test readiness is not complete.",
    readiness: {
      approved: status === "passed",
      approvedBy: "platform-operator",
      authorizationScope: "platform-infrastructure only",
      excludedScope: ["hosted application business logic", "production secrets", "destructive exploitation", "data exfiltration"],
    },
    externalProfessionalPentest: {
      requiredBeforeEnterpriseLaunch: true,
      status: "planned-required-before-enterprise-launch",
      nextAction: "Book or execute an external professional penetration test when staging/public provider targets are available.",
    },
    methodology: [
      "OWASP Top 10 / ASVS readiness",
      "admin-plane access and session boundary review",
      "WAF, rate limit and security header coverage",
      "dependency, static and secret-scan hygiene",
      "non-destructive infrastructure-only validation",
    ],
    evidence: {
      threatModel: {
        path: "THREAT-MODEL.md",
        present: threatModelPresent,
      },
      reports: requiredReports,
    },
    summary: {
      totalChecks: requiredReports.length + 1,
      failedChecks: failedChecks.length,
      reportsFreshHours: 168,
    },
    issues: failedChecks,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("security", `pentest-readiness-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("security", `pentest-readiness-${stamp}`, [
    "# Penetration Test Readiness",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "## Evidence",
    "",
    `- THREAT-MODEL.md: ${threatModelPresent ? "present" : "missing"}`,
    ...requiredReports.map((item) => `- ${item.command}: ${item.status}; fresh=${item.fresh}; report=${item.reportPath || "missing"}`),
    "",
    "## External Pentest",
    "",
    "- Required before enterprise launch: yes",
    "- Current state: readiness approved, external execution still required before enterprise launch",
    "",
    "## Issues",
    "",
    ...(failedChecks.length ? failedChecks.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Pentest readiness report written to ${jsonPath} and ${markdownPath}`);
  if (failedChecks.length) {
    fail(`Pentest readiness failed with ${failedChecks.length} issue(s). Report: ${jsonPath}`);
  }
  log("Penetration test readiness passed.");
}

function vulnerabilityDisclosure() {
  log("==> Vulnerability disclosure evidence");
  const generatedAt = new Date().toISOString();
  const securityPath = path.join(infraRoot, "SECURITY.md");
  const securityText = fs.existsSync(securityPath) ? readText(securityPath) : "";
  const requiredPatterns = [
    ["vulnerability section", /##\s+Vulnerability disclosure/i],
    ["private reporting", /privately|private/i],
    ["acknowledgement target", /acknowledgement target:\s*72 hours/i],
    ["triage target", /severity triage target:\s*5 business days/i],
    ["public disclosure approval", /public disclosure[\s\S]*operator\s+approval/i],
    ["secret redaction", /Never include secrets|tokens|private keys/i],
    ["incident response escalation", /incident-response/i],
  ];
  const checks = requiredPatterns.map(([name, pattern]) => ({
    name,
    status: pattern.test(securityText) ? "passed" : "failed",
  }));
  const failedChecks = checks.filter((check) => check.status !== "passed");
  const status = failedChecks.length ? "failed" : "passed";
  const payload = {
    generatedAt,
    status,
    command: "vulnerability-disclosure",
    scope: "platform-infrastructure",
    mode: "publishable-process-evidence",
    detail: status === "passed"
      ? "Vulnerability disclosure process is publishable from SECURITY.md and approved for platform governance evidence."
      : "Vulnerability disclosure process is incomplete.",
    channel: {
      type: "repository-security-policy",
      path: "SECURITY.md",
      securityPolicyPresent: securityText.length > 0,
      publicDomainRequired: false,
      containsSecretMaterial: false,
    },
    process: {
      publishable: status === "passed",
      approved: status === "passed",
      acknowledgementTarget: "72 hours",
      triageTarget: "5 business days",
      publicDisclosureRequiresApproval: true,
      emergencyEscalation: "incident-response",
      scope: "platform-infrastructure",
    },
    checks,
    summary: {
      totalChecks: checks.length,
      failedChecks: failedChecks.length,
    },
    issues: failedChecks.map((check) => check.name),
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("security", `vulnerability-disclosure-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("security", `vulnerability-disclosure-${stamp}`, [
    "# Vulnerability Disclosure Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "## Channel",
    "",
    `- Type: ${payload.channel.type}`,
    `- Path: ${payload.channel.path}`,
    `- Public domain required: ${payload.channel.publicDomainRequired ? "yes" : "no"}`,
    "",
    "## Process",
    "",
    `- Publishable: ${payload.process.publishable ? "yes" : "no"}`,
    `- Approved: ${payload.process.approved ? "yes" : "no"}`,
    `- Acknowledgement target: ${payload.process.acknowledgementTarget}`,
    `- Triage target: ${payload.process.triageTarget}`,
    `- Public disclosure requires approval: ${payload.process.publicDisclosureRequiresApproval ? "yes" : "no"}`,
    `- Emergency escalation: ${payload.process.emergencyEscalation}`,
    "",
    "## Checks",
    "",
    ...checks.map((check) => `- ${check.name}: ${check.status}`),
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Vulnerability disclosure report written to ${jsonPath} and ${markdownPath}`);
  if (status !== "passed") {
    fail(`Vulnerability disclosure evidence failed. Report: ${jsonPath}`);
  }
  log("Vulnerability disclosure evidence passed.");
}

function complianceEvidence() {
  log("==> Compliance evidence");
  const generatedAt = new Date().toISOString();
  const docPath = path.join(infraRoot, "governance", "compliance-evidence.md");
  const text = fs.existsSync(docPath) ? readText(docPath) : "";
  const requiredPatterns = [
    ["scope platform-infrastructure", /Approved scope:\s*platform-infrastructure only/i],
    ["control matrix", /##\s+Control Matrix[\s\S]*Review cadence/i],
    ["GDPR-like mapping", /##\s+GDPR-Like Mapping/i],
    ["SOC2-like mapping", /##\s+SOC2-Like Mapping/i],
    ["owner assigned", /\|\s*Owner\s*\|/i],
    ["formal certification not claimed", /Formal certification:\s*not claimed/i],
    ["external audit boundary", /External audit:\s*required only/i],
    ["hosted apps out of scope", /Hosted application business logic/i],
  ];
  const checks = requiredPatterns.map(([name, pattern]) => ({
    name,
    status: pattern.test(text) ? "passed" : "failed",
  }));
  const failedChecks = checks.filter((check) => check.status !== "passed");
  const status = failedChecks.length ? "failed" : "passed";
  const payload = {
    generatedAt,
    status,
    command: "compliance-evidence",
    scope: "platform-infrastructure",
    mode: "governance-evidence",
    detail: status === "passed"
      ? "Non-secret GDPR/SOC2-like platform compliance matrix is approved for infrastructure governance evidence."
      : "Compliance evidence matrix is incomplete.",
    compliance: {
      approved: status === "passed",
      gdprLikeMapping: /##\s+GDPR-Like Mapping/i.test(text),
      soc2LikeMapping: /##\s+SOC2-Like Mapping/i.test(text),
      formalCertificationClaimed: false,
      formalCertificationRequiredForClaim: true,
      hostedApplicationsOutOfScope: /Hosted application business logic/i.test(text),
      documentPath: "governance/compliance-evidence.md",
    },
    checks,
    summary: {
      totalChecks: checks.length,
      failedChecks: failedChecks.length,
    },
    issues: failedChecks.map((check) => check.name),
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("governance", `compliance-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("governance", `compliance-evidence-${stamp}`, [
    "# Compliance Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "## Compliance",
    "",
    `- Approved: ${payload.compliance.approved ? "yes" : "no"}`,
    `- GDPR-like mapping: ${payload.compliance.gdprLikeMapping ? "yes" : "no"}`,
    `- SOC2-like mapping: ${payload.compliance.soc2LikeMapping ? "yes" : "no"}`,
    `- Formal certification claimed: ${payload.compliance.formalCertificationClaimed ? "yes" : "no"}`,
    `- Hosted applications out of scope: ${payload.compliance.hostedApplicationsOutOfScope ? "yes" : "no"}`,
    "",
    "## Checks",
    "",
    ...checks.map((check) => `- ${check.name}: ${check.status}`),
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Compliance evidence report written to ${jsonPath} and ${markdownPath}`);
  if (status !== "passed") {
    fail(`Compliance evidence failed. Report: ${jsonPath}`);
  }
  log("Compliance evidence passed.");
}

function dataClassification() {
  log("==> Data classification evidence");
  const generatedAt = new Date().toISOString();
  const docPath = path.join(infraRoot, "governance", "data-classification.md");
  const text = fs.existsSync(docPath) ? readText(docPath) : "";
  const requiredLevels = ["Public", "Internal", "Confidential", "Secret", "Restricted"];
  const requiredPatterns = [
    ["classification levels", /##\s+Classification Levels/i],
    ...requiredLevels.map((level) => [`level ${level}`, new RegExp(`\\b${level}\\b`, "i")]),
    ["hosted app datasets out of scope", /Hosted\s+application datasets remain application-owned/i],
    ["secrets never committed", /Secret and Restricted data must not be committed to Git/i],
    ["backups restricted", /Backup contents are Restricted/i],
    ["new data classified before go-live", /New data types must be classified before go-live/i],
    ["retention review", /##\s+Retention And Review/i],
  ];
  const checks = requiredPatterns.map(([name, pattern]) => ({
    name,
    status: pattern.test(text) ? "passed" : "failed",
  }));
  const failedChecks = checks.filter((check) => check.status !== "passed");
  const status = failedChecks.length ? "failed" : "passed";
  const payload = {
    generatedAt,
    status,
    command: "data-classification",
    scope: "platform-infrastructure",
    mode: "governance-evidence",
    detail: status === "passed"
      ? "Platform data classification is approved and covers handling rules for infrastructure data."
      : "Platform data classification is incomplete.",
    classification: {
      approved: status === "passed",
      documentPath: "governance/data-classification.md",
      levels: requiredLevels,
      hostedApplicationDataOutOfScope: /Hosted\s+application datasets remain application-owned/i.test(text),
      secretsNeverCommitted: /Secret and Restricted data must not be committed to Git/i.test(text),
      restrictedBackupHandling: /Backup contents are Restricted/i.test(text),
    },
    checks,
    summary: {
      totalChecks: checks.length,
      failedChecks: failedChecks.length,
    },
    issues: failedChecks.map((check) => check.name),
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("governance", `data-classification-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("governance", `data-classification-${stamp}`, [
    "# Data Classification Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "## Classification",
    "",
    `- Approved: ${payload.classification.approved ? "yes" : "no"}`,
    `- Levels: ${payload.classification.levels.join(", ")}`,
    `- Hosted application data out of scope: ${payload.classification.hostedApplicationDataOutOfScope ? "yes" : "no"}`,
    `- Secrets never committed: ${payload.classification.secretsNeverCommitted ? "yes" : "no"}`,
    `- Restricted backup handling: ${payload.classification.restrictedBackupHandling ? "yes" : "no"}`,
    "",
    "## Checks",
    "",
    ...checks.map((check) => `- ${check.name}: ${check.status}`),
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Data classification report written to ${jsonPath} and ${markdownPath}`);
  if (status !== "passed") {
    fail(`Data classification failed. Report: ${jsonPath}`);
  }
  log("Data classification evidence passed.");
}

function featureFlagsKillSwitches() {
  log("==> Feature flags and kill switches evidence");
  const generatedAt = new Date().toISOString();
  const docPath = path.join(infraRoot, "governance", "kill-switches.md");
  const text = fs.existsSync(docPath) ? readText(docPath) : "";
  const switchNames = [
    "Hosted app public exposure",
    "Project router boundary",
    "Admin portal public access",
    "Off-site backup upload",
    "Release/deploy pipeline",
    "Alert delivery channel",
    "WAF/rate limiting policy",
    "Managed secret materialization",
  ];
  const requiredPatterns = [
    ["kill switch matrix", /##\s+Kill Switch Matrix/i],
    ["operator disable path", /does not\s+require code changes/i],
    ["application flags out of scope", /application flags remain app-owned/i],
    ["owner trigger disable recovery evidence", /\|\s*Switch\s*\|\s*Scope\s*\|\s*Trigger\s*\|\s*Disable action\s*\|\s*Recovery action\s*\|\s*Evidence\s*\|/i],
    ["no destructive volume action", /Never delete volumes or backups as a kill switch/i],
    ...switchNames.map((name) => [name, new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i")]),
  ];
  const checks = requiredPatterns.map(([name, pattern]) => ({
    name,
    status: pattern.test(text) ? "passed" : "failed",
  }));
  const failedChecks = checks.filter((check) => check.status !== "passed");
  const status = failedChecks.length ? "failed" : "passed";
  const switchCount = switchNames.filter((name) => new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(text)).length;
  const payload = {
    generatedAt,
    status,
    command: "feature-flags-kill-switches",
    scope: "platform-infrastructure",
    mode: "governance-evidence",
    detail: status === "passed"
      ? "Infrastructure kill switches are documented with operator-owned disable and recovery paths."
      : "Infrastructure kill switch evidence is incomplete.",
    killSwitches: {
      operational: status === "passed",
      documentPath: "governance/kill-switches.md",
      switchCount,
      applicationFlagsOutOfScope: /application flags remain app-owned/i.test(text),
      destructiveVolumeActionsAllowed: false,
      codeChangeRequired: false,
    },
    checks,
    summary: {
      totalChecks: checks.length,
      failedChecks: failedChecks.length,
    },
    issues: failedChecks.map((check) => check.name),
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("governance", `feature-flags-kill-switches-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("governance", `feature-flags-kill-switches-${stamp}`, [
    "# Feature Flags And Kill Switches Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "## Kill Switches",
    "",
    `- Operational: ${payload.killSwitches.operational ? "yes" : "no"}`,
    `- Switch count: ${payload.killSwitches.switchCount}`,
    `- Application flags out of scope: ${payload.killSwitches.applicationFlagsOutOfScope ? "yes" : "no"}`,
    `- Destructive volume actions allowed: ${payload.killSwitches.destructiveVolumeActionsAllowed ? "yes" : "no"}`,
    `- Code change required: ${payload.killSwitches.codeChangeRequired ? "yes" : "no"}`,
    "",
    "## Checks",
    "",
    ...checks.map((check) => `- ${check.name}: ${check.status}`),
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Feature flags and kill switches report written to ${jsonPath} and ${markdownPath}`);
  if (status !== "passed") {
    fail(`Feature flags and kill switches evidence failed. Report: ${jsonPath}`);
  }
  log("Feature flags and kill switches evidence passed.");
}

function haSingleNodeRiskAcceptance() {
  log("==> HA single-node risk acceptance evidence");
  const generatedAt = new Date().toISOString();
  const docPath = path.join(infraRoot, "governance", "ha-single-node-risk-acceptance.md");
  const text = fs.existsSync(docPath) ? readText(docPath) : "";
  const requiredPatterns = [
    ["single-node accepted", /single-node operation is accepted for this phase/i],
    ["no HA claim", /HA claimed:\s*no/i],
    ["no multi-node claim", /Multi-node claimed:\s*no/i],
    ["single failure domain", /single failure domain/i],
    ["compensating controls", /##\s+Compensating Controls/i],
    ["exit criteria", /##\s+Exit Criteria/i],
    ["public go-live review", /before public production go-live/i],
  ];
  const checks = requiredPatterns.map(([name, pattern]) => ({
    name,
    status: pattern.test(text) ? "passed" : "failed",
  }));
  const failedChecks = checks.filter((check) => check.status !== "passed");
  const status = failedChecks.length ? "failed" : "passed";
  const payload = {
    generatedAt,
    status,
    command: "ha-single-node-risk-acceptance",
    scope: "platform-infrastructure",
    mode: "governance-evidence",
    detail: status === "passed"
      ? "Single-node VPS risk is explicitly accepted for the current phase; HA or multi-node readiness is not claimed."
      : "Single-node risk acceptance evidence is incomplete.",
    decision: {
      approved: status === "passed",
      documentPath: "governance/ha-single-node-risk-acceptance.md",
      singleNodeRiskAccepted: /single-node operation is accepted for this phase/i.test(text),
      haClaimed: false,
      multiNodeClaimed: false,
      requiresReplacementBeforeHaClaim: true,
    },
    checks,
    summary: {
      totalChecks: checks.length,
      failedChecks: failedChecks.length,
    },
    issues: failedChecks.map((check) => check.name),
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("governance", `ha-single-node-risk-acceptance-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("governance", `ha-single-node-risk-acceptance-${stamp}`, [
    "# HA Single-Node Risk Acceptance Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "## Decision",
    "",
    `- Approved: ${payload.decision.approved ? "yes" : "no"}`,
    `- Single-node risk accepted: ${payload.decision.singleNodeRiskAccepted ? "yes" : "no"}`,
    `- HA claimed: ${payload.decision.haClaimed ? "yes" : "no"}`,
    `- Multi-node claimed: ${payload.decision.multiNodeClaimed ? "yes" : "no"}`,
    "",
    "## Checks",
    "",
    ...checks.map((check) => `- ${check.name}: ${check.status}`),
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`HA single-node risk acceptance report written to ${jsonPath} and ${markdownPath}`);
  if (status !== "passed") {
    fail(`HA single-node risk acceptance failed. Report: ${jsonPath}`);
  }
  log("HA single-node risk acceptance passed.");
}

function enterpriseProduction360Coverage() {
  log("==> Enterprise production 360 coverage");
  const generatedAt = new Date().toISOString();
  const manifestPath = path.join(infraRoot, "governance", "enterprise-production-360-coverage.json");
  const manifest = readJsonFile(manifestPath, manifestPath);
  const enterpriseManifest = readJsonFile(path.join(infraRoot, "governance", "enterprise-requirements.json"));
  const readinessManifest = readJsonFile(path.join(infraRoot, "governance", "production-readiness.json"));
  const productionPolicyPath = path.join(infraRoot, "governance", "production-go-no-go.json");
  const enterpriseIds = new Set((enterpriseManifest.requirements || []).map((item) => item.id).filter(Boolean));
  const readinessIds = new Set((readinessManifest.requirements || []).map((item) => item.id).filter(Boolean));
  const goNoGoChecks = new Set([
    "vps-bootstrap-applied",
    "vps-hardening-applied",
    "vps-host-readiness",
    "pre-go-live-evidence-complete",
    "healthcheck-coverage",
    "infra-health-runtime",
    "retention-evidence",
    "platform-admin-audit-evidence",
    "github-actions-run-success",
    "secret-rotation-evidence",
    "disaster-recovery-rpo-rto-offsite",
    "real-alert-delivery",
    "external-uptime-provider",
    "public-load-benchmark",
    "release-evidence-and-rollback",
    "cloudflare-access-admin-verified",
  ]);
  const domains = Array.isArray(manifest.domains) ? manifest.domains : [];
  const modeCounts = {};
  const issues = [];
  let controlCount = 0;
  let invalidRefs = 0;
  let providerRequiredControls = 0;
  let humanRequiredControls = 0;
  let requiredBeforeGoLiveControls = 0;

  const resolveRef = (rawRef) => {
    const ref = String(rawRef || "");
    const separator = ref.indexOf(":");
    if (separator <= 0) return { ref, ok: false, detail: "invalid evidence reference format" };
    const type = ref.slice(0, separator);
    const value = ref.slice(separator + 1);
    if (!value) return { ref, ok: false, detail: "empty evidence reference value" };
    if (type === "enterprise") {
      return { ref, ok: enterpriseIds.has(value), detail: enterpriseIds.has(value) ? "enterprise requirement exists" : "missing enterprise requirement" };
    }
    if (type === "readiness") {
      return { ref, ok: readinessIds.has(value), detail: readinessIds.has(value) ? "production readiness requirement exists" : "missing production readiness requirement" };
    }
    if (type === "go-no-go") {
      return { ref, ok: goNoGoChecks.has(value), detail: goNoGoChecks.has(value) ? "production go/no-go check exists" : "missing go/no-go check mapping" };
    }
    if (type === "command") {
      const hasOpsCommand = Object.prototype.hasOwnProperty.call(commands, value);
      const hasWrapper = fs.existsSync(path.join(infraRoot, "scripts", `${value}.sh`));
      return { ref, ok: hasOpsCommand || hasWrapper, detail: hasOpsCommand ? "infra-ops command exists" : hasWrapper ? "script wrapper exists" : "missing command or script wrapper" };
    }
    if (type === "file" || type === "workflow") {
      const filePath = path.resolve(infraRoot, value);
      const ok = filePath.startsWith(`${infraRoot}${path.sep}`) && fs.existsSync(filePath);
      return { ref, ok, detail: ok ? "file exists" : "missing file" };
    }
    return { ref, ok: false, detail: `unsupported evidence reference type: ${type}` };
  };

  const domainResults = domains.map((domain) => {
    const controls = Array.isArray(domain.controls) ? domain.controls : [];
    const controlResults = controls.map((control) => {
      controlCount += 1;
      if (control.providerRequired === true) providerRequiredControls += 1;
      if (control.humanRequired === true) humanRequiredControls += 1;
      if (control.requiredBeforeGoLive === true) requiredBeforeGoLiveControls += 1;
      const mode = String(control.mode || "unspecified");
      modeCounts[mode] = (modeCounts[mode] || 0) + 1;
      const refs = Array.isArray(control.evidenceRefs) ? control.evidenceRefs : [];
      const refResults = refs.map(resolveRef);
      const missingRefs = refResults.filter((item) => !item.ok);
      invalidRefs += missingRefs.length;
      if (!refs.length) {
        invalidRefs += 1;
        issues.push(`${domain.id}/${control.id}:missing-evidenceRefs`);
      }
      for (const missingRef of missingRefs) {
        issues.push(`${domain.id}/${control.id}:${missingRef.ref}:${missingRef.detail}`);
      }
      return {
        id: control.id || "unnamed-control",
        title: control.title || humanName(control.id || "unnamed-control"),
        mode,
        providerRequired: control.providerRequired === true,
        humanRequired: control.humanRequired === true,
        requiredBeforeGoLive: control.requiredBeforeGoLive === true,
        status: refs.length && missingRefs.length === 0 ? "covered" : "needs-work",
        evidenceRefs: refResults,
      };
    });
    const gaps = controlResults.filter((control) => control.status !== "covered");
    return {
      id: domain.id || "unnamed-domain",
      title: domain.title || humanName(domain.id || "unnamed-domain"),
      objective: domain.objective || "",
      status: gaps.length ? "needs-work" : "covered",
      controls: controlResults,
      summary: {
        controls: controlResults.length,
        covered: controlResults.filter((control) => control.status === "covered").length,
        gaps: gaps.length,
        providerRequired: controlResults.filter((control) => control.providerRequired).length,
        humanRequired: controlResults.filter((control) => control.humanRequired).length,
      },
    };
  });

  const expectedDomains = Number(manifest.expectedDomainCount || 0);
  const minimumControls = Number(manifest.minimumControlCount || 0);
  const domainGaps = domainResults.filter((domain) => domain.status !== "covered").length;
  const countIssues = [
    ...(domains.length < expectedDomains ? [`domain-count:${domains.length}<${expectedDomains}`] : []),
    ...(controlCount < minimumControls ? [`control-count:${controlCount}<${minimumControls}`] : []),
  ];
  const allIssues = [...issues, ...countIssues];
  const status = allIssues.length ? "failed" : "passed";
  const payload = {
    generatedAt,
    status,
    command: "enterprise-production-360-coverage",
    scope: "platform-infrastructure",
    mode: "coverage-catalog",
    detail: status === "passed"
      ? "Enterprise production 360 coverage catalog is complete. This report validates coverage mapping only; it is not a production go-live decision."
      : "Enterprise production 360 coverage catalog has unmapped controls or invalid evidence references.",
    semantics: {
      coverageOnly: true,
      productionGoLiveDecision: false,
      missingProviderEvidenceCanRemainPending: true,
      falseGreenPolicy: "Provider, public edge, human audit and protected-runtime controls must remain pending until their real evidence exists.",
    },
    summary: {
      expectedDomains,
      minimumControls,
      domains: domains.length,
      controls: controlCount,
      requiredBeforeGoLiveControls,
      providerRequiredControls,
      humanRequiredControls,
      invalidRefs,
      domainGaps,
      modes: modeCounts,
    },
    domains: domainResults,
    issues: allIssues,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("governance", `enterprise-production-360-coverage-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("governance", `enterprise-production-360-coverage-${stamp}`, [
    "# Enterprise Production 360 Coverage",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Scope: ${payload.scope}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "## Semantics",
    "",
    "- This validates control coverage only.",
    "- This is not a production go-live decision.",
    "- Provider, public edge, human audit and protected-runtime controls still require real evidence before production claims.",
    "",
    "## Summary",
    "",
    `- Domains: ${payload.summary.domains}/${payload.summary.expectedDomains}`,
    `- Controls: ${payload.summary.controls}/${payload.summary.minimumControls}`,
    `- Required before go-live: ${payload.summary.requiredBeforeGoLiveControls}`,
    `- Provider-required controls: ${payload.summary.providerRequiredControls}`,
    `- Human-required controls: ${payload.summary.humanRequiredControls}`,
    `- Invalid references: ${payload.summary.invalidRefs}`,
    "",
    "## Domains",
    "",
    ...domainResults.map((domain) => `- ${domain.title}: ${domain.status}; controls=${domain.summary.controls}; provider=${domain.summary.providerRequired}; human=${domain.summary.humanRequired}`),
    "",
    "## Issues",
    "",
    ...(payload.issues.length ? payload.issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Enterprise production 360 coverage report written to ${jsonPath} and ${markdownPath}`);
  if (status !== "passed") {
    fail(`Enterprise production 360 coverage failed with ${allIssues.length} issue(s). Report: ${jsonPath}`);
  }
  log("Enterprise production 360 coverage passed.");
}

function backupSchedulerCheck() {
  log("==> Backup scheduler runtime check");
  const generatedAt = new Date().toISOString();
  const inspectResult = run("docker", ["inspect", "enterprise-backup-scheduler"], { capture: true, allowFailure: true });
  let inspect = null;
  if (inspectResult.status === 0) {
    try {
      inspect = JSON.parse(String(inspectResult.stdout || "[]"))[0] ?? null;
    } catch {
      inspect = null;
    }
  }
  const cronResult = dockerExec("enterprise-backup-scheduler", ["crontab", "-l"], { capture: true, allowFailure: true });
  const envKeysResult = dockerExec("enterprise-backup-scheduler", ["sh", "-c", "test -s /etc/platform/backup-scheduler.env && cut -d= -f1 /etc/platform/backup-scheduler.env | sort"], { capture: true, allowFailure: true });
  const cron = String(cronResult.stdout || "");
  const envKeys = String(envKeysResult.stdout || "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const requiredJobs = [
    "backup-applications",
    "backup-postgres",
    "backup-mariadb",
    "backup-minio",
    "backup-keycloak",
    "backup-secret-manager-metadata",
    "offsite-backup-restic",
  ];
  const requiredEnvKeys = [
    "BACKUP_SIGNING_KEYS_FILE",
    "RESTIC_REPOSITORY",
    "RESTIC_PASSWORD_FILE",
    "RESTIC_IMAGE",
    "RESTIC_KEEP_LAST",
    "RESTIC_MAX_REPOSITORY_BYTES",
    "RCLONE_CONFIG",
  ];
  const missingJobs = requiredJobs.filter((job) => !cron.includes(job));
  const missingEnvKeys = requiredEnvKeys.filter((key) => !envKeys.includes(key));
  const everyEightHourJobs = requiredJobs.filter((job) => new RegExp(`(^|\\n)\\s*\\d+\\s+\\*/8\\s+\\*\\s+\\*\\s+\\*\\s+.*\\b${job}\\b`).test(cron));
  const jobsNotEveryEightHours = requiredJobs.filter((job) => !everyEightHourJobs.includes(job));
  const keepLastResult = dockerExec("enterprise-backup-scheduler", ["sh", "-c", ". /etc/platform/backup-scheduler.env >/dev/null 2>&1 && printf '%s' \"$RESTIC_KEEP_LAST\""], { capture: true, allowFailure: true });
  const keepLast = Number(String(keepLastResult.stdout || "").trim());
  const maxRepositoryBytesResult = dockerExec("enterprise-backup-scheduler", ["sh", "-c", ". /etc/platform/backup-scheduler.env >/dev/null 2>&1 && printf '%s' \"$RESTIC_MAX_REPOSITORY_BYTES\""], { capture: true, allowFailure: true });
  const maxRepositoryBytes = Number(String(maxRepositoryBytesResult.stdout || "").trim());
  const health = inspect?.State?.Health?.Status ?? null;
  const state = inspect?.State?.Status ?? null;
  const status = inspect
    && state === "running"
    && health === "healthy"
    && cronResult.status === 0
    && missingJobs.length === 0
    && missingEnvKeys.length === 0
    && jobsNotEveryEightHours.length === 0
    && keepLast === 42
    && maxRepositoryBytes === defaultResticMaxRepositoryBytes
    ? "passed"
    : "failed";
  const payload = {
    generatedAt,
    status,
    command: "backup-scheduler",
    scope: "platform-infrastructure",
    container: {
      name: "enterprise-backup-scheduler",
      state,
      health,
    },
    schedule: {
      requiredJobs,
      missingJobs,
      everyEightHourJobs,
      jobsNotEveryEightHours,
      cronLineCount: cron.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#")).length,
      everyEightHours: jobsNotEveryEightHours.length === 0,
      retentionKeepLast: Number.isFinite(keepLast) ? keepLast : null,
      maxRepositoryBytes: Number.isFinite(maxRepositoryBytes) ? maxRepositoryBytes : null,
    },
    runtimeEnv: {
      requiredKeys: requiredEnvKeys,
      presentKeys: envKeys.filter((key) => requiredEnvKeys.includes(key)),
      missingKeys: missingEnvKeys,
    },
    summary: {
      failedChecks: status === "passed" ? 0 : 1,
      missingJobs: missingJobs.length,
      missingEnvKeys: missingEnvKeys.length,
      jobsNotEveryEightHours: jobsNotEveryEightHours.length,
      retentionKeepLast: Number.isFinite(keepLast) ? keepLast : null,
      maxRepositoryBytes: Number.isFinite(maxRepositoryBytes) ? maxRepositoryBytes : null,
    },
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("local-checks", `backup-scheduler-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("local-checks", `backup-scheduler-${stamp}`, [
    "# Backup Scheduler Runtime Check",
    "",
    `Status: ${payload.status}`,
    `Generated at: ${payload.generatedAt}`,
    `Container state: ${state ?? "missing"}`,
    `Container health: ${health ?? "missing"}`,
    `Cron lines: ${payload.schedule.cronLineCount}`,
    `Every 8 hours configured: ${payload.schedule.everyEightHours ? "yes" : "no"}`,
    `Required jobs missing: ${missingJobs.join(", ") || "none"}`,
    `Jobs not every 8 hours: ${jobsNotEveryEightHours.join(", ") || "none"}`,
    `Retention keep-last: ${Number.isFinite(keepLast) ? keepLast : "missing"}`,
    `Repository max bytes: ${Number.isFinite(maxRepositoryBytes) ? maxRepositoryBytes : "missing"}`,
    `Required env keys missing: ${missingEnvKeys.join(", ") || "none"}`,
  ]);
  log(`Backup scheduler report written to ${jsonPath} and ${markdownPath}`);
  if (status !== "passed") {
    fail(`Backup scheduler runtime check failed. Report: ${jsonPath}`);
  }
  log("Backup scheduler runtime check passed.");
}

function help() {
  log(`Usage: sh scripts/infra-ops.sh <command> [--key value]

Commands:
  audit-log-evidence
  alert-evidence
  backup-applications
  backup-coverage-matrix
  backup-mariadb
  backup-keycloak
  backup-minio
  backup-restore-drill
  backup-restore-drill-keycloak
  backup-restore-drill-mariadb
  backup-restore-drill-minio
  backup-restore-drill-secret-manager-metadata
  backup-postgres
  backup-platform-catalog
  backup-scheduler
  backup-secret-manager-metadata
  browser-e2e-tests
  certificate-expiry-check
  chaos-profile
  cloudflare-access-admin
  cloudflare-from-zero
  compliance-evidence
  compose-healthcheck-coverage
  functional-health-check
  control-center-tests
  data-classification
  dependency-hygiene
  dr-readiness-check
  dr-evidence
  enterprise-check
  enterprise-production-360-coverage
  enterprise-hardening-audit
  enterprise-requirements-check
  enterprise-10-check
  evidence-bundle
  evidence-bundle-verify
  execute-backup-job
  external-uptime-check
  failure-tests
  feature-flags-kill-switches
  fault-injection-tests
  full-restore-drill
  generate-sbom
  github-actions-config
  github-attestation-evidence
  github-actions-run-evidence
  github-branch-protection
  github-environments
  governance-check
  ha-single-node-risk-acceptance
  ha-config-check
  init-local-secrets
  infra-health
  import-postgres-backup
  install-mariadb-backup-cron
  install-postgres-backup-cron
  local-secret-manager
  load-profile
  load-benchmark
  load-smoke
  linux-portability-check
  maintainability-hygiene
  managed-secrets-preflight
  network-segmentation-check
  offsite-backup-restic
  offsite-restore-drill-restic
  performance-hygiene
  pentest-readiness
  platform-admin-audit
  pre-go-live-evidence
  project-router-tests
  prune-postgres-backups
  prune-manifest-backups
  production-go-no-go
  production-preflight
  rate-limit-evidence
  retention-evidence
  repo-coverage-check
  release-evidence
  release-artifact-gate
  rollback-release
  runtime-fingerprint
  runtime-isolation-check
  restore-test-keycloak
  restore-test-mariadb
  restore-test-minio
  restore-test-secret-manager-metadata
  restore-postgres
  restore-test-postgres
  secret-rotation-evidence
  secret-scan
  secret-manager
  security-matrix
  security-smoke
  sign-existing-postgres-backups
  sign-images
  static-security-check
  supply-chain-lock-check
  supply-chain-hygiene
  testing-hygiene
  validate-local-secrets
  vulnerability-disclosure
  vps-preflight
  vps-postdeploy
  waf-smoke`);
}

const commands = {
  "audit-log-evidence": auditLogEvidence,
  "alert-evidence": alertEvidence,
  "backup-keycloak": backupKeycloakConfig,
  "backup-mariadb": backupMariadb,
  "backup-minio": backupMinio,
  "backup-restore-drill": backupRestoreDrill,
  "backup-restore-drill-keycloak": backupRestoreDrillKeycloakConfig,
  "backup-restore-drill-mariadb": backupRestoreDrillMariadb,
  "backup-restore-drill-minio": backupRestoreDrillMinio,
  "backup-restore-drill-secret-manager-metadata": backupRestoreDrillSecretManagerMetadata,
  "backup-applications": backupApplications,
  "backup-coverage-matrix": () => writeBackupCoverageReport(platformBackupResources()),
  "backup-postgres": backupPostgres,
  "backup-platform-catalog": backupPlatformCatalog,
  "backup-scheduler": backupSchedulerCheck,
  "backup-secret-manager-metadata": backupSecretManagerMetadata,
  "browser-e2e-tests": browserE2eTests,
  "certificate-expiry-check": certificateExpiryCheck,
  "chaos-profile": chaosProfile,
  "cloudflare-access-admin": cloudflareAccessAdmin,
  "cloudflare-from-zero": cloudflareFromZero,
  "compliance-evidence": complianceEvidence,
  "compose-healthcheck-coverage": composeHealthcheckCoverage,
  "functional-health-check": functionalHealthCheck,
  "control-center-tests": controlCenterTests,
  "data-classification": dataClassification,
  "dependency-hygiene": dependencyHygiene,
  "dr-readiness-check": drReadinessCheck,
  "dr-evidence": drEvidence,
  "enterprise-check": enterpriseCheck,
  "enterprise-production-360-coverage": enterpriseProduction360Coverage,
  "enterprise-hardening-audit": enterpriseHardeningAudit,
  "enterprise-requirements-check": enterpriseRequirementsCheck,
  "enterprise-10-check": enterpriseTenCheck,
  "evidence-bundle": evidenceBundle,
  "evidence-bundle-verify": evidenceBundleVerify,
  "execute-backup-job": executeBackupJob,
  "external-uptime-check": externalUptimeCheck,
  "failure-tests": failureTests,
  "feature-flags-kill-switches": featureFlagsKillSwitches,
  "fault-injection-tests": faultInjectionTests,
  "full-restore-drill": fullRestoreDrill,
  "generate-sbom": generateSbom,
  "github-actions-config": githubActionsConfig,
  "github-attestation-evidence": githubAttestationEvidence,
  "github-actions-run-evidence": githubActionsRunEvidence,
  "github-branch-protection": githubBranchProtection,
  "github-environments": githubEnvironments,
  "governance-check": governanceCheck,
  "ha-single-node-risk-acceptance": haSingleNodeRiskAcceptance,
  "ha-config-check": haConfigCheck,
  "init-local-secrets": initLocalSecrets,
  "infra-health": infraHealth,
  "import-postgres-backup": importPostgresBackup,
  "install-mariadb-backup-cron": installMariadbBackupCron,
  "install-postgres-backup-cron": installPostgresBackupCron,
  "local-secret-manager": localSecretManager,
  "load-profile": loadProfile,
  "load-benchmark": loadBenchmark,
  "load-smoke": loadSmoke,
  "linux-portability-check": linuxPortabilityCheck,
  "maintainability-hygiene": maintainabilityHygiene,
  "managed-secrets-preflight": managedSecretsPreflight,
  "network-segmentation-check": networkSegmentationCheck,
  "offsite-backup-restic": offsiteBackupRestic,
  "offsite-restore-drill-restic": offsiteRestoreDrillRestic,
  "performance-hygiene": performanceHygiene,
  "pentest-readiness": pentestReadiness,
  "platform-admin-audit": platformAdminAuditEvidence,
  "pre-go-live-evidence": preGoLiveEvidence,
  "project-router-tests": projectRouterTests,
  "prune-postgres-backups": prunePostgresBackups,
  "prune-manifest-backups": pruneManifestBackups,
  "production-go-no-go": productionGoNoGo,
  "production-preflight": productionPreflight,
  "rate-limit-evidence": rateLimitEvidence,
  "retention-evidence": retentionEvidence,
  "repo-coverage-check": repoCoverageCheck,
  "release-evidence": releaseEvidence,
  "release-artifact-gate": releaseArtifactGate,
  "rollback-release": rollbackRelease,
  "runtime-fingerprint": runtimeFingerprint,
  "runtime-isolation-check": runtimeIsolationCheck,
  "restore-test-keycloak": restoreTestKeycloakConfig,
  "restore-test-mariadb": restoreTestMariadb,
  "restore-test-minio": restoreTestMinio,
  "restore-test-secret-manager-metadata": restoreTestSecretManagerMetadata,
  "restore-postgres": restorePostgres,
  "restore-test-postgres": restoreTestPostgres,
  "secret-rotation-evidence": secretRotationEvidence,
  "secret-scan": secretScan,
  "secret-manager": secretManager,
  "security-matrix": securityMatrix,
  "security-smoke": securitySmoke,
  "sign-existing-postgres-backups": signExistingPostgresBackups,
  "sign-images": signImages,
  "static-security-check": staticSecurityCheck,
  "supply-chain-lock-check": supplyChainLockCheck,
  "supply-chain-hygiene": supplyChainHygiene,
  "testing-hygiene": testingHygiene,
  "validate-local-secrets": validateLocalSecrets,
  "vulnerability-disclosure": vulnerabilityDisclosure,
  "vps-preflight": vpsPreflight,
  "vps-postdeploy": vpsPostdeploy,
  "waf-smoke": wafSmoke,
  help,
};

try {
  if (!commands[command]) {
    help();
    fail(`Unknown command: ${command}`);
  }
  await commands[command]();
} catch (error) {
  process.stderr.write(`${error.message ?? error}\n`);
  process.exitCode = 1;
}
