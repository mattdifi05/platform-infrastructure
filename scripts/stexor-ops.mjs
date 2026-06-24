#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const infraRoot = path.resolve(scriptDir, "..");
const command = process.argv[2] ?? "help";
const argv = parseArgs(process.argv.slice(3));
const configuredSourceRoot = process.env.STEXOR_SOURCE_ROOT ?? process.env.NODE_SOURCE_DIR ?? argv.sourceRoot;
const sourceRoot = configuredSourceRoot ? path.resolve(infraRoot, configuredSourceRoot) : path.resolve(infraRoot, "..", "src_stexor");
const defaultNodeImage = "node:26.3.1-alpine@sha256:a2dc166a387cc6ca1e62d0c8e265e49ca985d6e60abc9fe6e6c3d6ce8e63f606";
const defaultPlaywrightImage = "mcr.microsoft.com/playwright:v1.60.0-noble";

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

function booleanFlag(value) {
  return value === true || value === "true" || value === "1" || value === "yes";
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
  const result = spawnSync(bin, args, {
    cwd: options.cwd ?? infraRoot,
    env: { ...process.env, ...options.env },
    input: options.input,
    encoding: options.encoding ?? "utf8",
    maxBuffer: options.maxBuffer ?? 64 * 1024 * 1024,
    stdio: options.capture
      ? ["pipe", "pipe", "pipe"]
      : [options.input ? "pipe" : "inherit", "inherit", "inherit"],
  });
  if (result.error) {
    if (options.allowFailure) {
      return {
        status: 1,
        stdout: "",
        stderr: String(result.error.message ?? result.error),
      };
    }
    throw result.error;
  }
  if (result.status !== 0 && !options.allowFailure) {
    const details = [result.stderr, result.stdout].filter(Boolean).join("\n").trim();
    fail(`${bin} ${args.join(" ")} failed${details ? `:\n${details}` : ""}`);
  }
  return result;
}

function output(bin, args = [], options = {}) {
  const result = run(bin, args, { ...options, capture: true });
  return String(result.stdout ?? "").trim();
}

function runSecretManager(args, options = {}) {
  return run(process.execPath, [path.join(scriptDir, "stexor-secret-manager.mjs"), ...args], options);
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

function recordBackupRestoreRun({ container, database, databaseName = database, user, operation, status, artifactPath = null, artifactSha256 = null, startedAt, metadata = {} }) {
  const finishedAt = new Date();
  const started = startedAt instanceof Date ? startedAt : finishedAt;
  const durationMs = Math.max(0, finishedAt.getTime() - started.getTime());
  const pathValue = artifactPath ? sqlString(artifactPath) : "null";
  const shaValue = artifactSha256 ? sqlString(artifactSha256) : "null";
  const metadataValue = sqlString(JSON.stringify(metadata));
  postgres(container, database, user, `
    create extension if not exists pgcrypto;
    create schema if not exists stexor_platform;
    create table if not exists stexor_platform.backup_restore_runs (
      id uuid primary key default gen_random_uuid(),
      operation text not null check (operation in ('backup', 'restore', 'restore_test')),
      status text not null check (status in ('started', 'success', 'failed')),
      database_name text not null,
      artifact_path text,
      artifact_sha256 text check (artifact_sha256 is null or artifact_sha256 ~ '^[a-f0-9]{64}$'),
      started_at timestamptz not null default now(),
      finished_at timestamptz,
      duration_ms integer check (duration_ms is null or duration_ms >= 0),
      metadata jsonb not null default '{}'::jsonb,
      check ((status = 'started' and finished_at is null) or (status <> 'started' and finished_at is not null)),
      check (finished_at is null or finished_at >= started_at)
    );
    insert into stexor_platform.backup_restore_runs (
      operation,
      status,
      database_name,
      artifact_path,
      artifact_sha256,
      started_at,
      finished_at,
      duration_ms,
      metadata
    )
    values (
      ${sqlString(operation)},
      ${sqlString(status)},
      ${sqlString(databaseName)},
      ${pathValue},
      ${shaValue},
      ${sqlString(started.toISOString())}::timestamptz,
      ${sqlString(finishedAt.toISOString())}::timestamptz,
      ${durationMs},
      ${metadataValue}::jsonb
    );
  `);
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
      const scanText = relativePath.replaceAll("\\", "/") === "scripts/stexor-ops.mjs"
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
  if (!pattern.test(text)) {
    fail(message);
  }
}

function assertNoMatch(text, pattern, message) {
  if (pattern.test(text)) {
    fail(message);
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
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
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
  const keys = parseVersionedSecretKeys(value);
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
  return `stexor-postgres-backup-v1\n${fileName}\n${hash}\n`;
}

function signBackupArtifact(filePath, hash = sha256File(filePath)) {
  const fileName = path.basename(filePath);
  const activeKey = backupSigningKeys()[0];
  const signature = crypto.createHmac("sha256", activeKey.secret).update(backupSignatureMessage(fileName, hash)).digest("base64url");
  const sidecar = {
    version: 1,
    algorithm: "HMAC-SHA256",
    keyId: activeKey.id,
    artifact: fileName,
    sha256: hash,
    signature,
    signedAt: new Date().toISOString(),
  };
  fs.writeFileSync(backupSignatureSidecarPath(filePath), `${JSON.stringify(sidecar, null, 2)}\n`, "utf8");
  return { hash, keyId: activeKey.id, signaturePath: backupSignatureSidecarPath(filePath) };
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
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function ensureBackupOutputDir(directory) {
  fs.mkdirSync(directory, { recursive: true });
  return resolveInside(backupRootPath(), directory);
}

function recordDatabaseBackupEvidence({ engine, sourceContainer, operation, status, artifactPath = null, artifactSha256 = null, startedAt, metadata = {} }) {
  if (booleanFlag(argv.skipEvidence)) {
    return;
  }
  const evidenceContainer = argv.evidenceContainer ?? "enterprise-postgres";
  const evidenceDatabase = argv.evidenceDatabase ?? "stexor_app";
  const evidenceUser = argv.evidenceUser ?? "postgres";
  try {
    recordBackupRestoreRun({
      container: evidenceContainer,
      database: evidenceDatabase,
      databaseName: `${engine}-all`,
      user: evidenceUser,
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
  fs.writeFileSync(jsonPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return jsonPath;
}

function writeMarkdownReport(directoryName, baseName, lines) {
  const directory = ensureReportDir(directoryName);
  const markdownPath = path.join(directory, `${baseName}.md`);
  fs.writeFileSync(markdownPath, `${lines.join("\n")}\n`, "utf8");
  return markdownPath;
}

function writeBackupExecutionReport({
  engine,
  sourceContainer,
  status,
  artifactPath = null,
  artifactSha256 = null,
  signature = null,
  startedAt,
  metadata = {},
}) {
  const finishedAt = new Date();
  const started = startedAt instanceof Date ? startedAt : finishedAt;
  const artifactExists = artifactPath ? fs.existsSync(artifactPath) : false;
  const artifactSizeBytes = artifactExists ? fs.statSync(artifactPath).size : null;
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
    `# Stexor ${engine} Backup Report`,
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

function writeBackupIntegritySidecars(hostPath) {
  const hash = sha256File(hostPath);
  fs.writeFileSync(`${hostPath}.sha256`, `${hash}  ${path.basename(hostPath)}\n`, "ascii");
  const signature = signBackupArtifact(hostPath, hash);
  return { hash, signature };
}

function hostPathForContainerMount(filePath) {
  const resolved = path.resolve(filePath).replaceAll("\\", "/");
  const mappings = [
    [process.env.STEXOR_INFRA_CONTAINER_ROOT || infraRoot, process.env.STEXOR_INFRA_HOST_ROOT],
    [sourceRoot, process.env.STEXOR_SOURCE_HOST_ROOT],
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
    "enterprise-backend",
    "enterprise-web",
    "enterprise-worker-notifications",
    "enterprise-worker-jobs",
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
  "BACKEND_IMAGE",
  "WEB_IMAGE",
  "WORKER_NOTIFICATIONS_IMAGE",
  "WORKER_JOBS_IMAGE",
];

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

function normalizeDigestValue(value) {
  const text = String(value ?? "").trim().toLowerCase();
  const match = text.match(/^(?:sha256:)?([a-f0-9]{64})$/);
  return match ? match[1] : null;
}

function decodeBase64Json(value, label) {
  try {
    return JSON.parse(Buffer.from(String(value), "base64").toString("utf8"));
  } catch (error) {
    fail(`Invalid ${label}: ${String(error?.message ?? error)}`);
  }
}

function inTotoStatementsFromDocument(document) {
  if (Array.isArray(document)) {
    return document.flatMap((entry) => inTotoStatementsFromDocument(entry));
  }
  if (!document || typeof document !== "object") {
    fail("SLSA provenance must be a JSON object, DSSE envelope, bundle or array.");
  }
  if (document.payload && typeof document.payload === "string") {
    return inTotoStatementsFromDocument(decodeBase64Json(document.payload, "DSSE provenance payload"));
  }
  if (Array.isArray(document.attestations)) {
    return document.attestations.flatMap((entry) => inTotoStatementsFromDocument(entry));
  }
  if (Array.isArray(document.statements)) {
    return document.statements.flatMap((entry) => inTotoStatementsFromDocument(entry));
  }
  if (document.statement && typeof document.statement === "object") {
    return inTotoStatementsFromDocument(document.statement);
  }
  return [document];
}

function collectSubjectDigests(statement) {
  return (Array.isArray(statement.subject) ? statement.subject : [])
    .map((subject) => {
      const digests = subject?.digest && typeof subject.digest === "object" ? Object.entries(subject.digest) : [];
      const sha256 = digests
        .filter(([algorithm]) => algorithm.toLowerCase() === "sha256")
        .map(([, value]) => normalizeDigestValue(value))
        .find(Boolean);
      return sha256 ? { name: subject.name ?? null, sha256 } : null;
    })
    .filter(Boolean);
}

function valueContainsText(value, needle) {
  if (!needle) {
    return true;
  }
  if (typeof value === "string") {
    return value.includes(needle);
  }
  if (Array.isArray(value)) {
    return value.some((entry) => valueContainsText(entry, needle));
  }
  if (value && typeof value === "object") {
    return Object.values(value).some((entry) => valueContainsText(entry, needle));
  }
  return false;
}

function validateSlsaProvenance({ provenancePath, images, releaseSha, requireReleaseSha = true }) {
  const resolved = path.resolve(provenancePath);
  const document = readJsonFile(resolved, resolved);
  const statements = inTotoStatementsFromDocument(document);
  if (!statements.length) {
    fail("SLSA provenance does not contain an in-toto statement.");
  }

  const imageDigests = images
    .map((image) => ({ image, sha256: digestFromImageRef(image) }))
    .filter((entry) => entry.image);
  const missingImageDigest = imageDigests.find((entry) => !entry.sha256);
  if (missingImageDigest) {
    fail(`Cannot validate provenance for unpinned image: ${missingImageDigest.image}`);
  }

  const slsaStatements = statements.filter((statement) => statement?.predicateType === "https://slsa.dev/provenance/v1");
  if (!slsaStatements.length) {
    fail("SLSA provenance must use predicateType https://slsa.dev/provenance/v1.");
  }
  for (const statement of slsaStatements) {
    if (!Array.isArray(statement.subject) || !statement.subject.length) {
      fail("SLSA provenance statements must include at least one subject.");
    }
    if (!statement.predicate?.buildDefinition?.buildType) {
      fail("SLSA provenance v1 must include predicate.buildDefinition.buildType.");
    }
  }

  const subjectDigests = slsaStatements.flatMap(collectSubjectDigests);
  const subjectDigestSet = new Set(subjectDigests.map((subject) => subject.sha256));
  const missingSubjects = imageDigests.filter((entry) => !subjectDigestSet.has(entry.sha256));
  if (missingSubjects.length) {
    fail(`SLSA provenance subjects do not cover release images: ${missingSubjects.map((entry) => entry.image).join(", ")}`);
  }

  const releaseShaMatched = !releaseSha || slsaStatements.some((statement) => valueContainsText(statement.predicate?.buildDefinition, releaseSha)
    || valueContainsText(statement.predicate?.runDetails, releaseSha)
    || valueContainsText(statement.subject, releaseSha));
  if (requireReleaseSha && releaseSha && !releaseShaMatched) {
    fail(`SLSA provenance does not reference release commit ${releaseSha}. Use --skipProvenanceCommitCheck only for a reviewed provider exception.`);
  }

  return {
    status: "passed",
    predicateType: "https://slsa.dev/provenance/v1",
    statementCount: slsaStatements.length,
    subjectCount: subjectDigests.length,
    releaseImageDigests: imageDigests.map((entry) => entry.sha256),
    matchedSubjects: imageDigests.map((entry) => ({
      image: entry.image,
      sha256: entry.sha256,
      subjects: subjectDigests.filter((subject) => subject.sha256 === entry.sha256).map((subject) => subject.name),
    })),
    releaseSha,
    releaseShaMatched,
    requireReleaseSha,
  };
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
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "stexor-rollback-"));
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
      "# Stexor Rollback Plan",
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
  const dumps = listDumpFilesRecursive(backupRoot);
  let signed = 0;
  let verified = 0;
  for (const dump of dumps) {
    const hash = sha256File(dump);
    const shaPath = `${dump}.sha256`;
    if (!fs.existsSync(shaPath) || fs.readFileSync(shaPath, "utf8").trim().split(/\s+/, 1)[0] !== hash) {
      fs.writeFileSync(shaPath, `${hash}  ${path.basename(dump)}\n`, "ascii");
    }
    if (fs.existsSync(backupSignatureSidecarPath(dump)) && !booleanFlag(argv.force)) {
      verifyBackupArtifact(dump);
      verified += 1;
      continue;
    }
    signBackupArtifact(dump, hash);
    signed += 1;
  }
  log(`Backup signatures ready: signed=${signed} verified=${verified} total=${dumps.length}.`);
}

function backendSessionSigningKey() {
  const keyText = dockerExecOutput("enterprise-backend", [
    "sh",
    "-c",
    [
      'if [ -s /run/secrets/session_signing_keys ]; then cat /run/secrets/session_signing_keys;',
      'elif [ -s /run/secrets/session_secret ]; then printf "current=%s" "$(cat /run/secrets/session_secret)";',
      'fi',
    ].join(" "),
  ]).trim();
  const keys = parseVersionedSecretKeys(keyText);
  const activeKey = keys[0];
  if (!activeKey) {
    fail("Cannot read backend session signing key for integration signing.");
  }
  return activeKey;
}

function backendSecretHash(value) {
  const keys = parseVersionedSecretKeys(dockerExecOutput("enterprise-backend", [
    "sh",
    "-c",
    'if [ -s /run/secrets/hash_pepper_keys ]; then cat /run/secrets/hash_pepper_keys; fi',
  ]).trim());
  const activeKey = keys[0];
  if (activeKey) {
    return `${activeKey.id}:${hmacHex(activeKey.secret, value)}`;
  }
  const sessionSecret = dockerExecOutput("enterprise-backend", [
    "sh",
    "-c",
    'if [ -s /run/secrets/session_secret ]; then cat /run/secrets/session_secret; fi',
  ]).trim();
  return hmacHex(sessionSecret, value);
}

function newSignedCookie(signingKey, accountId, sessionId) {
  const now = Math.floor(Date.now() / 1000);
  const fingerprint = hmacHex(signingKey.secret, "session-fingerprint:unknown").slice(0, 32);
  const payload = JSON.stringify({
    accountId,
    sessionId,
    fp: fingerprint,
    iat: now,
    exp: now + 315360000,
    kid: signingKey.id,
  });
  const encoded = base64url(payload);
  const signature = crypto.createHmac("sha256", signingKey.secret).update(encoded).digest("base64url");
  return `stexor_session=${encoded}.${signature}`;
}

function redisCommand(args, options = {}) {
  const script = [
    'if [ -s /run/secrets/redis_password ]; then REDISCLI_AUTH=$(cat /run/secrets/redis_password); export REDISCLI_AUTH; fi;',
    'redis-cli "$@"',
  ].join(" ");
  return dockerExec("enterprise-redis", ["sh", "-c", script, "sh", ...args], options);
}

function redisSetValue(key, value, ttlMs) {
  const script = [
    'if [ -s /run/secrets/redis_password ]; then REDISCLI_AUTH=$(cat /run/secrets/redis_password); export REDISCLI_AUTH; fi;',
    'redis-cli -x set "$1" >/dev/null && redis-cli pexpire "$1" "$2" >/dev/null',
  ].join(" ");
  dockerExec("enterprise-redis", ["sh", "-c", script, "sh", key, String(ttlMs)], { input: value });
}

function redisSetPlainValue(key, value, ttlMs) {
  redisCommand(["set", key, value, "px", String(ttlMs)]);
}

function redisDelete(keys) {
  if (!keys.length) {
    return;
  }
  redisCommand(["del", ...keys], { allowFailure: true, capture: true });
}

const localTlsHostnames = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "ui.localhost.com",
  "account.localhost.com",
  "api.localhost.com",
  "auth.localhost.com",
  "minio.localhost.com",
  "grafana.localhost.com",
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

function cookieFromHeaders(headers, name) {
  const values = headers["set-cookie"];
  const list = Array.isArray(values) ? values : values ? [values] : [];
  for (const cookie of list) {
    const match = cookie.match(new RegExp(`^${name}=([^;]+)`));
    if (match) {
      return `${name}=${match[1]}`;
    }
  }
  return null;
}

function assertStatus(response, expected, name) {
  if (response.status !== expected) {
    fail(`${name} expected HTTP ${expected}, got ${response.status}: ${response.text}`);
  }
}

function pnpmInWeb(commandLine, options = {}) {
  const bootstrap = `cd /workspace && export HOME=/tmp XDG_DATA_HOME=/tmp/xdg PNPM_HOME=/tmp/pnpm-home npm_config_cache=/tmp/npm-cache && if [ ! -f /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ]; then npm install --prefix /tmp/pnpm-run --no-save pnpm@11.9.0 >/dev/null; fi && node /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ${commandLine}`;
  return dockerExec("enterprise-web", ["sh", "-lc", bootstrap], options);
}

function pnpmInWebOutput(commandLine) {
  const bootstrap = `cd /workspace && export HOME=/tmp XDG_DATA_HOME=/tmp/xdg PNPM_HOME=/tmp/pnpm-home npm_config_cache=/tmp/npm-cache && if [ ! -f /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ]; then npm install --prefix /tmp/pnpm-run --no-save pnpm@11.9.0 >/dev/null; fi && node /tmp/pnpm-run/node_modules/pnpm/bin/pnpm.mjs ${commandLine}`;
  return dockerExecOutput("enterprise-web", ["sh", "-lc", bootstrap]);
}

function configuredNodeImage() {
  return process.env.NODE_IMAGE || parseEnv(path.join(infraRoot, ".env")).NODE_IMAGE || defaultNodeImage;
}

function configuredPlaywrightImage() {
  return process.env.PLAYWRIGHT_IMAGE || parseEnv(path.join(infraRoot, ".env")).PLAYWRIGHT_IMAGE || defaultPlaywrightImage;
}

function runSourceWorkspaceInDocker(script, options = {}) {
  const sourceMount = hostPathForContainerMount(sourceRoot);
  const infraMount = hostPathForContainerMount(infraRoot);
  run("docker", [
    "run",
    "--rm",
    "-e",
    "CI=true",
    "-e",
    "NEXT_TELEMETRY_DISABLED=1",
    "-v",
    `${sourceMount}:/source:ro`,
    "-v",
    `${infraMount}:/stexor-platform-infrastructure:ro`,
    configuredNodeImage(),
    "sh",
    "-lc",
    script,
  ], options);
}

function sourceWorkspaceOutput(commands, options = {}) {
  const sourceMount = hostPathForContainerMount(sourceRoot);
  const infraMount = hostPathForContainerMount(infraRoot);
  return output("docker", [
    "run",
    "--rm",
    "-e",
    "CI=true",
    "-e",
    "NEXT_TELEMETRY_DISABLED=1",
    "-v",
    `${sourceMount}:/source:ro`,
    "-v",
    `${infraMount}:/stexor-platform-infrastructure:ro`,
    configuredNodeImage(),
    "sh",
    "-lc",
    sourceWorkspaceBootstrap(commands),
  ], options);
}

function sourceWorkspaceBootstrap(commands) {
  const excludes = [
    "./.artifacts",
    "./.codex-*.log",
    "./.docker-build-cache",
    "./.git",
    "./.next",
    "./*/.next",
    "./.pnpm-store",
    "./coverage",
    "./dist",
    "./*/dist",
    "./node_modules",
    "./*/node_modules",
    "./playwright-report",
    "./test-results",
  ].map((pattern) => `--exclude='${pattern}'`).join(" ");
  return [
    "set -eu",
    "mkdir -p /workspace",
    "cd /source",
    `tar ${excludes} -cf - . | tar -xf - -C /workspace`,
    "cd /workspace",
    "npm install -g pnpm@11.9.0 >/dev/null",
    commands,
  ].join(" && ");
}

async function accessReview() {
  const database = argv.database ?? "stexor_app";
  log("==> Active account roles");
  postgres("enterprise-postgres", database, "postgres", `
select
  account.email::text,
  role.role,
  role.granted_at,
  role.revoked_at
from stexor_account.account_roles role
join stexor_account.accounts account on account.id = role.account_id
where account.deleted_at is null
order by account.email, role.role;
`);
  log("==> Active sessions older than 30 days");
  postgres("enterprise-postgres", database, "postgres", `
select
  account.email::text,
  session.device,
  session.browser,
  session.last_seen_at,
  session.auth_method
from stexor_account.sessions session
join stexor_account.accounts account on account.id = session.account_id
where session.status = 'active'
  and session.last_seen_at < now() - interval '30 days'
order by session.last_seen_at asc;
`);
  log("Access review completed.");
}

async function applyPostgresMigrations() {
  const container = argv.container ?? "enterprise-postgres";
  const database = argv.database ?? "stexor_app";
  const user = argv.user ?? "postgres";
  const migrationDir = path.join(infraRoot, "postgres", "migrations");
  const files = fs.readdirSync(migrationDir)
    .filter((file) => file.endsWith(".sql"))
    .sort()
    .map((file) => path.join(migrationDir, file));

  if (!files.length) {
    log(`No migrations found in ${migrationDir}`);
    return;
  }

  postgres(container, database, user, "create schema if not exists stexor_platform; create table if not exists stexor_platform.schema_migrations (version text primary key, applied_at timestamptz not null default now(), checksum text not null default '');");

  for (const file of files) {
    const version = path.basename(file, ".sql");
    const checksum = sha256File(file);
    const existing = postgresOut(container, database, user, `select checksum from stexor_platform.schema_migrations where version = ${sqlString(version)};`);
    if (existing) {
      if (existing.trim() !== checksum) {
        fail(`Migration ${version} was already applied with a different checksum.`);
      }
      log(`Skipping ${version} (already applied)`);
      continue;
    }
    log(`Applying ${version}`);
    run("docker", ["cp", file, `${container}:/tmp/stexor-migration.sql`]);
    dockerExec(container, ["psql", "-U", user, "-d", database, "-v", "ON_ERROR_STOP=1", "-f", "/tmp/stexor-migration.sql"]);
    postgres(container, database, user, `insert into stexor_platform.schema_migrations (version, checksum) values (${sqlString(version)}, ${sqlString(checksum)});`);
    dockerExec(container, ["rm", "-f", "/tmp/stexor-migration.sql"]);
  }

  log("PostgreSQL migrations complete.");
}

async function backupPostgres(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? "stexor_app";
  const user = options.user ?? argv.user ?? "postgres";
  const outputDir = path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "postgres"));
  const startedAt = new Date();
  fs.mkdirSync(outputDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const fileName = `${database}-${timestamp}.dump`;
  const containerPath = `/tmp/${fileName}`;
  const hostPath = path.join(outputDir, fileName);

  try {
    log(`Creating PostgreSQL backup for database '${database}'...`);
    dockerExec(container, ["pg_dump", "-U", user, "-d", database, "--format=custom", "--no-owner", "--no-acl", `--file=${containerPath}`]);
    run("docker", ["cp", `${container}:${containerPath}`, hostPath]);
    dockerExec(container, ["rm", "-f", containerPath]);

    const hash = sha256File(hostPath);
    fs.writeFileSync(`${hostPath}.sha256`, `${hash}  ${fileName}\n`, "ascii");
    const signature = signBackupArtifact(hostPath, hash);
    recordBackupRestoreRun({ container, database, user, operation: "backup", status: "success", artifactPath: hostPath, artifactSha256: hash, startedAt });
    writeBackupExecutionReport({
      engine: "postgres",
      sourceContainer: container,
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
      signature,
      startedAt,
      metadata: { database, format: "pg_dump-custom" },
    });
    log(`Backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, container, database, user };
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

async function certificateExpiryCheck() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const defaultHosts = [
    env.UI_HOST ?? "ui.localhost.com",
    env.ACCOUNT_HOST ?? "account.localhost.com",
    env.API_HOST ?? "api.localhost.com",
  ].join(",");
  const hosts = (argv.hosts ?? defaultHosts).split(",").map((host) => host.trim()).filter(Boolean);
  const warnDays = Number(argv.warnDays ?? 30);
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
}

async function enterpriseCheck() {
  log("==> Workspace typecheck/build in disposable Linux container");
  runSourceWorkspaceInDocker(sourceWorkspaceBootstrap([
    "node scripts/dependency-hygiene.mjs",
    "node scripts/testing-hygiene.mjs",
    "node scripts/maintainability-hygiene.mjs",
    "node scripts/performance-hygiene.mjs",
    "pnpm install --frozen-lockfile",
    "pnpm deps:supply-chain -- --sbom-output /workspace/security/sbom/pnpm-sbom-current.cdx.json",
    "pnpm -r typecheck",
    "pnpm typecheck:e2e",
    "pnpm peers check",
    "pnpm -r --if-present test",
    "pnpm --filter ./apps/web build",
    "node scripts/performance-hygiene.mjs --built",
  ].join(" && ")));
  run("docker", ["compose", "--env-file", path.join(infraRoot, ".env"), "-p", "stexor_platform_local", "-f", path.join(infraRoot, "compose.yaml"), "config", "--quiet"]);
  await enterpriseHardeningAudit();
  log("Enterprise local quality gate passed.");
}

async function enterpriseHardeningAudit() {
  const projectName = argv.projectName ?? "stexor_platform_local";
  await staticSecurityCheck();
  await dependencyHygiene();
  await supplyChainHygiene();
  await testingHygiene();
  await faultInjectionTests();
  await maintainabilityHygiene();
  await performanceHygiene();
  log("==> Compose local config");
  run("docker", ["compose", "--env-file", ".env", "-p", projectName, "config", "--quiet"]);
  log("==> Compose build config");
  run("docker", ["compose", "--env-file", ".env", "-p", projectName, "-f", "compose.yaml", "-f", "compose.build.yaml", "config", "--quiet"]);
  if (fs.existsSync(path.join(infraRoot, "compose.secrets.yaml"))) {
    await validateLocalSecrets();
    log("==> Compose local secrets config");
    run("docker", ["compose", "--env-file", ".env", "-p", projectName, "-f", "compose.yaml", "-f", "compose.secrets.yaml", "config", "--quiet"]);
  }
  log("==> Compose prod config");
  run("docker", ["compose", "--env-file", ".env", "-p", "enterprise_prod", "-f", "compose.yaml", "-f", "compose.prod.yaml", "config", "--quiet"]);
  await applyPostgresMigrations();
  await backupRestoreDrill();
  await backupRestoreDrillMariadb();
  await backupRestoreDrillMinio();
  await backupRestoreDrillKeycloakConfig();
  await backupRestoreDrillSecretManagerMetadata();
  await prunePostgresBackups({ dryRun: true });
  await securitySmoke();
  await accountIntegrationTests();
  await browserE2eTests();
  await certificateExpiryCheck();
  await loadSmoke();
  await secretScan();
  await runtimeHealthChecks();
  log("Enterprise hardening audit passed.");
}

async function browserE2eTests() {
  log("==> Browser E2E tests");
  const env = parseEnv(path.join(infraRoot, ".env"));
  const playwrightBaseUrl = env.NEXT_PUBLIC_UI_URL ?? env.UI_PUBLIC_URL ?? "https://ui.localhost.com";
  const sourceMount = hostPathForContainerMount(sourceRoot);
  const bootstrap = [
    "set -eu",
    "if ! command -v docker >/dev/null; then apt-get update >/dev/null && apt-get install -y docker.io >/dev/null; fi",
    sourceWorkspaceBootstrap([
      "pnpm install --frozen-lockfile",
      "pnpm typecheck:e2e",
      "pnpm test:e2e",
    ].join(" && ")),
  ].join(" && ");
  run("docker", [
    "run",
    "--rm",
    "--network",
    "container:enterprise-traefik",
    "-e",
    "CI=true",
    "-e",
    "NEXT_TELEMETRY_DISABLED=1",
    "-e",
    `PLAYWRIGHT_BASE_URL=${playwrightBaseUrl}`,
    "-e",
    "PLAYWRIGHT_HTML_OPEN=never",
    "-e",
    "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1",
    "-v",
    "/var/run/docker.sock:/var/run/docker.sock",
    "-v",
    `${sourceMount}:/source:ro`,
    configuredPlaywrightImage(),
    "bash",
    "-lc",
    bootstrap,
  ]);
  log("Browser E2E tests passed.");
}

async function runtimeHealthChecks() {
  const runtimeContainers = [
    "enterprise-traefik",
    "enterprise-postgres",
    "enterprise-redis",
    "enterprise-keycloak",
    "enterprise-nats",
    "enterprise-minio",
    "enterprise-backend",
    "enterprise-web",
    "enterprise-worker-notifications",
    "enterprise-worker-jobs",
    "enterprise-prometheus",
    "enterprise-node-exporter",
    "enterprise-cadvisor",
    "enterprise-alertmanager",
    "enterprise-grafana",
    "enterprise-loki",
    "enterprise-promtail",
  ];
  log("==> Container health");
  for (const container of runtimeContainers) {
    const status = output("docker", ["inspect", "--format", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", container]);
    if (!/^running( healthy)?$/.test(status.trim())) {
      fail(`${container} is not healthy: ${status}`);
    }
  }

  log("==> Container runtime guardrails");
  for (const container of runtimeContainers) {
    const [inspect] = JSON.parse(output("docker", ["inspect", container]));
    const hostConfig = inspect?.HostConfig ?? {};
    const securityOpt = hostConfig.SecurityOpt ?? [];
    const logConfig = hostConfig.LogConfig ?? {};
    const logOptions = logConfig.Config ?? {};
    if (hostConfig.Init !== true) {
      fail(`${container} must run with init: true.`);
    }
    if (!Number.isInteger(hostConfig.PidsLimit) || hostConfig.PidsLimit <= 0) {
      fail(`${container} must set a positive pids_limit.`);
    }
    if (!securityOpt.includes("no-new-privileges:true")) {
      fail(`${container} must set no-new-privileges.`);
    }
    if (logConfig.Type !== "json-file" || logOptions["max-size"] !== "10m" || logOptions["max-file"] !== "5") {
      fail(`${container} must use bounded json-file logging.`);
    }
    if ((inspect?.Mounts ?? []).some((mount) => mount.Destination === "/var/run/docker.sock" || mount.Source === "/var/run/docker.sock")) {
      fail(`${container} must not mount docker.sock.`);
    }
  }

  log("==> Redis runtime integration");
  const redisPing = dockerExecOutput("enterprise-redis", ["sh", "-c", 'if [ -s /run/secrets/redis_password ]; then REDISCLI_AUTH=$(cat /run/secrets/redis_password); export REDISCLI_AUTH; fi; redis-cli ping']);
  if (!/PONG/.test(redisPing)) {
    fail("Redis ping failed");
  }
  const metrics = dockerExecOutput("enterprise-backend", ["wget", "-q", "-O", "-", "http://127.0.0.1:3000/metrics"]);
  if (!/redis_connection_up\{service="enterprise-backend"\} 1/.test(metrics)) {
    fail("Backend Redis metric is not up");
  }
  const alertmanagerStatus = dockerExecOutput("enterprise-alertmanager", ["wget", "-q", "-O", "-", "http://127.0.0.1:9093/-/healthy"]);
  if (!/OK/.test(alertmanagerStatus)) {
    fail("Alertmanager health endpoint is not OK.");
  }
  for (const worker of ["enterprise-worker-notifications", "enterprise-worker-jobs"]) {
    const health = dockerExecOutput(worker, ["wget", "-q", "-O", "-", "http://127.0.0.1:3000/health"]);
    if (!/"redis":"ok"/.test(health)) {
      fail(`${worker} Redis health is not ok`);
    }
  }

  log("==> Session policy coherence");
  const backendSessionTtl = dockerExecOutput("enterprise-backend", ["sh", "-c", 'printf "%s" "$SESSION_COOKIE_MAX_AGE_SECONDS"']).trim();
  if (backendSessionTtl !== "315360000") {
    fail("Backend remember-me TTL must be 315360000 seconds.");
  }
  const policySessionTtl = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select value->>'rememberMeSeconds' from stexor_account.security_policies where key = 'account_session';").trim();
  if (policySessionTtl !== "315360000") {
    fail("Database account_session policy rememberMeSeconds must be 315360000.");
  }

  log("==> App DB least privilege");
  for (const role of ["stexor_app_account_rw", "stexor_app_auth_rw", "stexor_app_audit_rw"]) {
    const roleMembership = postgresOut("enterprise-postgres", "stexor_app", "postgres", `select pg_has_role('stexor_app_user', ${sqlString(role)}, 'member');`).trim();
    if (roleMembership !== "t") {
      fail(`stexor_app_user must inherit ${role}.`);
    }
  }
  const directDelete = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_user', 'stexor_account.accounts', 'delete');").trim();
  if (directDelete !== "f") {
    fail("stexor_app_user must not have DELETE on stexor_account.accounts.");
  }
  postgresOut("enterprise-postgres", "stexor_app", "postgres", "set role stexor_app_user; select count(*) from stexor_account.accounts;");

  log("==> Row-level security");
  const rlsGapCount = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'stexor_account' and c.relkind in ('r','p') and (not c.relrowsecurity or not c.relforcerowsecurity);").trim();
  if (rlsGapCount !== "0") {
    fail("All stexor_account tables must have forced row-level security.");
  }
  const rlsPolicy = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select value->>'enabled' from stexor_account.security_policies where key = 'row_level_security';").trim();
  if (rlsPolicy !== "true") {
    fail("row_level_security policy must be recorded and enabled.");
  }

  log("==> Persistence integrity readiness");
  const migration006 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '006_persistence_integrity_readiness';").trim();
  if (migration006 !== "1") {
    fail("Persistence integrity migration 006 must be applied.");
  }
  const migration007 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '007_durable_audit_outbox';").trim();
  if (migration007 !== "1") {
    fail("Durable audit outbox migration 007 must be applied.");
  }
  const migration008 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '008_audit_account_unlink';").trim();
  if (migration008 !== "1") {
    fail("Audit account unlink migration 008 must be applied.");
  }
  const migration009 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '009_audit_outbox_dispatcher';").trim();
  if (migration009 !== "1") {
    fail("Audit outbox dispatcher migration 009 must be applied.");
  }
  const migration010 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '010_platform_runtime_least_privilege';").trim();
  if (migration010 !== "1") {
    fail("Platform runtime least-privilege migration 010 must be applied.");
  }
  const migration011 = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.schema_migrations where version = '011_platform_runtime_role_revoke';").trim();
  if (migration011 !== "1") {
    fail("Platform runtime inherited role revoke migration 011 must be applied.");
  }
  const runtimePlatformMutation = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_user', 'stexor_platform.schema_migrations', 'insert,update,delete') or has_table_privilege('stexor_app_user', 'stexor_platform.data_retention_policies', 'insert,update,delete') or has_table_privilege('stexor_app_user', 'stexor_platform.backup_restore_runs', 'insert,update,delete');").trim();
  if (runtimePlatformMutation !== "f") {
    fail("stexor_app_user must not mutate platform migration, retention or backup/restore evidence tables.");
  }
  const retentionPolicies = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.data_retention_policies where enabled;").trim();
  if (Number.parseInt(retentionPolicies, 10) < 6) {
    fail("At least six enabled data retention policies must be present.");
  }
  const backupRestoreLog = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_platform.backup_restore_runs') is not null;").trim();
  if (backupRestoreLog !== "t") {
    fail("Backup and restore run log table must exist.");
  }
  const successfulRestoreTests = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.backup_restore_runs where operation = 'restore_test' and status = 'success';").trim();
  if (Number.parseInt(successfulRestoreTests, 10) < 1) {
    fail("At least one successful PostgreSQL restore-test drill must be recorded in stexor_platform.backup_restore_runs.");
  }
  const activeBackupSetIndex = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_account.idx_backup_code_sets_one_active') is not null;").trim();
  if (activeBackupSetIndex !== "t") {
    fail("Active backup-code uniqueness index must exist.");
  }
  const auditMutationDenied = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_events', 'update') or has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_events', 'delete');").trim();
  if (auditMutationDenied !== "f") {
    fail("Audit role must not be able to update or delete audit events.");
  }
  const auditAppendOnlyTrigger = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from pg_trigger where tgname = 'trg_audit_events_append_only' and tgenabled <> 'D';").trim();
  if (auditAppendOnlyTrigger !== "1") {
    fail("Audit append-only trigger must be enabled.");
  }
  const auditOutboxTable = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_account.audit_outbox') is not null;").trim();
  if (auditOutboxTable !== "t") {
    fail("Durable audit outbox table must exist.");
  }
  const auditOutboxPrivileges = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_outbox', 'insert') and has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_outbox', 'update') and not has_table_privilege('stexor_app_audit_rw', 'stexor_account.audit_outbox', 'delete');").trim();
  if (auditOutboxPrivileges !== "t") {
    fail("Audit role must enqueue and update audit outbox entries without delete privilege.");
  }
  const auditOutboxRetention = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from stexor_platform.data_retention_policies where key = 'audit_outbox' and enabled;").trim();
  if (auditOutboxRetention !== "1") {
    fail("Audit outbox retention policy must be enabled.");
  }
  const auditOutboxDeadStatus = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select count(*) from pg_constraint where conname = 'audit_outbox_status_known' and pg_get_constraintdef(oid) like '%dead%';").trim();
  if (auditOutboxDeadStatus !== "1") {
    fail("Audit outbox must support terminal dead-letter status.");
  }
  const auditOutboxDueIndex = postgresOut("enterprise-postgres", "stexor_app", "postgres", "select to_regclass('stexor_account.idx_audit_outbox_due_dispatch') is not null;").trim();
  if (auditOutboxDueIndex !== "t") {
    fail("Audit outbox must have a due-dispatch index for worker claims.");
  }
  log("==> Dev app container hardening");
  for (const container of ["enterprise-backend", "enterprise-web", "enterprise-worker-notifications", "enterprise-worker-jobs"]) {
    const readonly = output("docker", ["inspect", "--format", "{{.HostConfig.ReadonlyRootfs}}", container]).trim().toLowerCase();
    const capDrop = output("docker", ["inspect", "--format", "{{json .HostConfig.CapDrop}}", container]);
    const securityOpt = output("docker", ["inspect", "--format", "{{json .HostConfig.SecurityOpt}}", container]);
    if (readonly !== "true") {
      fail(`${container} root filesystem must be read-only.`);
    }
    if (!/ALL/.test(capDrop)) {
      fail(`${container} must drop all Linux capabilities.`);
    }
    if (!/no-new-privileges:true/.test(securityOpt)) {
      fail(`${container} must set no-new-privileges.`);
    }
  }
}

async function generateSbom() {
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "security", "sbom"));
  fs.mkdirSync(outputDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const outputFile = path.join(outputDir, `pnpm-sbom-${timestamp}.json`);
  const json = sourceWorkspaceOutput("pnpm install --frozen-lockfile >/dev/null && pnpm list --json --prod --depth 20", { maxBuffer: 128 * 1024 * 1024 });
  fs.writeFileSync(outputFile, `${json}\n`, "utf8");
  log(`SBOM written to ${outputFile}`);
}

async function dependencyHygiene() {
  log("==> Dependency hygiene");
  run(process.execPath, ["scripts/dependency-hygiene.mjs"], { cwd: sourceRoot });
}

async function cloudflareFromZero() {
  run(process.execPath, [path.join(scriptDir, "cloudflare-from-zero.mjs"), ...process.argv.slice(3)]);
}

async function cloudflareAccessAdmin() {
  run(process.execPath, [path.join(scriptDir, "cloudflare-access-admin.mjs"), ...process.argv.slice(3)]);
}

async function supplyChainHygiene() {
  log("==> Supply-chain SBOM/CVE/license gate");
  const result = sourceWorkspaceOutput(
    "pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store >/dev/null && pnpm deps:supply-chain -- --sbom-output /workspace/security/sbom/pnpm-sbom-current.cdx.json",
    { maxBuffer: 128 * 1024 * 1024 },
  );
  log(result);
}

async function testingHygiene() {
  log("==> Testing hygiene");
  run(process.execPath, ["scripts/testing-hygiene.mjs"], { cwd: sourceRoot });
}

async function faultInjectionTests() {
  log("==> Fault injection tests");
  const testOutput = sourceWorkspaceOutput([
    "pnpm install --frozen-lockfile --store-dir /tmp/pnpm-store >/dev/null",
    "node --import ./scripts/register-ts-extension-loader.mjs --test apps/backend/src/db-query.test.ts apps/backend/src/runtime/redis-store.test.ts apps/backend/src/runtime/session-auth.test.ts",
  ].join(" && "), { maxBuffer: 128 * 1024 * 1024 });
  log(testOutput);

  const timeoutProbe = postgres("enterprise-postgres", "stexor_app", "postgres", "begin; set local statement_timeout = '1ms'; select pg_sleep(0.05); rollback;", {
    allowFailure: true,
    capture: true,
  });
  const timeoutOutput = `${timeoutProbe.stderr ?? ""}\n${timeoutProbe.stdout ?? ""}`;
  if (timeoutProbe.status === 0 || !/statement timeout|canceling statement/i.test(timeoutOutput)) {
    fail("PostgreSQL fault injection must prove statement_timeout cancels slow statements.");
  }
  log("PostgreSQL timeout fault injection passed.");
}

async function failureTests() {
  await faultInjectionTests();
  await wafSmoke();
  if (!booleanFlag(argv.confirmServiceStop)) {
    log("Service stop failure tests are armed but not executed. Re-run with --confirmServiceStop in local/staging to stop and recover containers.");
    return;
  }
  const allTargets = [
    ["redis", "enterprise-redis"],
    ["mariadb", "mariadb"],
    ["postgres", "enterprise-postgres"],
    ["minio", "enterprise-minio"],
    ["keycloak", "enterprise-keycloak"],
    ["backend", "enterprise-backend"],
    ["worker-notifications", "enterprise-worker-notifications"],
    ["worker-jobs", "enterprise-worker-jobs"],
    ["nats", "enterprise-nats"],
    ["waf", "enterprise-waf"],
  ];
  const requested = new Set(String(argv.targets ?? allTargets.map(([name]) => name).join(",")).split(",").map((value) => value.trim()).filter(Boolean));
  const targets = allTargets.filter(([name]) => requested.has(name));
  if (!targets.length) {
    fail("No valid failure-test targets selected.");
  }
  const results = [];
  const stopped = [];
  try {
    for (const [name, container] of targets) {
      const startedAt = Date.now();
      log(`==> Failure probe: stopping ${container}`);
      run("docker", ["stop", "--time", "10", container], { capture: true });
      stopped.push(container);
      await sleep(1500);
      const healthProbe = run(process.execPath, [path.join(scriptDir, "stexor-ops.mjs"), "infra-health"], { allowFailure: true, capture: true });
      const outputText = `${healthProbe.stdout ?? ""}\n${healthProbe.stderr ?? ""}`;
      if (healthProbe.status === 0 || !outputText.includes(container)) {
        fail(`infra-health did not detect stopped ${container}.`);
      }
      log(`Detected ${container} failure.`);
      run("docker", ["start", container], { capture: true });
      stopped.pop();
      await waitContainerHealthy(container, 120);
      await waitInfraHealth(120);
      const durationMs = Date.now() - startedAt;
      results.push({ target: name, container, detected: true, recovered: true, durationMs });
      log(`Recovered ${container} in ${durationMs}ms.`);
    }
  } finally {
    for (const container of stopped.reverse()) {
      run("docker", ["start", container], { allowFailure: true, capture: true });
    }
  }
  const stamp = reportTimestamp();
  const payload = { generatedAt: new Date().toISOString(), targets: results };
  const jsonPath = writeJsonReport("failure-tests", `failure-tests-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("failure-tests", `failure-tests-${stamp}`, [
    "# Stexor Failure Tests",
    "",
    `Generated at: ${payload.generatedAt}`,
    "",
    "| Target | Container | Detected | Recovered | Duration ms |",
    "| --- | --- | --- | --- | ---: |",
    ...results.map((result) => `| ${result.target} | ${result.container} | ${result.detected ? "yes" : "no"} | ${result.recovered ? "yes" : "no"} | ${result.durationMs} |`),
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
    const health = run(process.execPath, [path.join(scriptDir, "stexor-ops.mjs"), "infra-health"], { allowFailure: true, capture: true });
    lastOutput = `${health.stdout ?? ""}\n${health.stderr ?? ""}`;
    if (health.status === 0) {
      return;
    }
    await sleep(3000);
  }
  fail(`infra-health did not recover within ${timeoutSeconds}s:\n${lastOutput}`);
}

async function maintainabilityHygiene() {
  log("==> Maintainability hygiene");
  run(process.execPath, ["scripts/maintainability-hygiene.mjs"], { cwd: sourceRoot });
}

async function performanceHygiene() {
  log("==> Performance hygiene");
  run(process.execPath, ["scripts/performance-hygiene.mjs"], { cwd: sourceRoot });
}

async function initLocalSecrets() {
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
  const secretsDir = path.resolve(argv.secretsDir ?? path.join(infraRoot, "secrets"));
  const force = Boolean(argv.force);
  const sanitizeEnv = Boolean(argv.sanitizeEnv);
  fs.mkdirSync(secretsDir, { recursive: true });
  const env = parseEnv(envFile);

  const existingSecret = (name) => {
    if (force) return null;
    const value = readSecretFileIfExists(path.join(secretsDir, `${name}.txt`));
    return isUsableSecret(value) ? value : null;
  };
  const secretValue = (name, bytes = 36) => existingSecret(name) ?? randomSecret(bytes);
  const versionedSecretValue = (name, fallbackId) => {
    const existing = existingSecret(name);
    if (existing) return existing;
    return `${fallbackId}=${randomSecret(48)}`;
  };
  const postgresSuper = secretValue("postgres_superuser_password");
  const appDbPassword = secretValue("app_db_password");
  const keycloakDbPassword = secretValue("keycloak_db_password");
  const redisPassword = secretValue("redis_password");
  const keycloakAdminPassword = secretValue("keycloak_admin_password");
  const natsPassword = secretValue("nats_password");
  const minioRootPassword = secretValue("minio_root_password");
  const mariadbRootPassword = secretValue("mariadb_root_password");
  const phpmyadminControlPassword = secretValue("phpmyadmin_control_password");
  const grafanaAdminPassword = secretValue("grafana_admin_password");
  const sessionSecret = secretValue("session_secret", 48);
  const sessionSigningKeys = versionedSecretValue("session_signing_keys", secretId("s"));
  const projectsGatewaySigningKeys = versionedSecretValue("projects_gateway_signing_keys", secretId("p"));
  const hashPepperKeys = versionedSecretValue("hash_pepper_keys", "local");
  const backupSigningKeys = versionedSecretValue("backup_signing_keys", secretId("b"));
  const smtpPassword = secretValue("smtp_password");
  const googleOAuthClientSecret = secretValue("google_oauth_client_secret");
  const appDbUser = env.APP_DB_USER || "stexor_app_user";
  const appDbName = env.APP_DB_NAME || "stexor_app";
  const natsUser = env.NATS_USER || "stexor";
  const databaseUrl = existingSecret("database_url") ?? `postgresql://${encodeURIComponent(appDbUser)}:${encodeURIComponent(appDbPassword)}@postgres:5432/${encodeURIComponent(appDbName)}`;
  const natsUrl = existingSecret("nats_url") ?? `nats://${encodeURIComponent(natsUser)}:${encodeURIComponent(natsPassword)}@nats:4222`;

  const writeSecretFile = (name, value) => {
    const filePath = path.join(secretsDir, `${name}.txt`);
    if (fs.existsSync(filePath) && !force) {
      return;
    }
    fs.writeFileSync(filePath, value, "utf8");
    try {
      fs.chmodSync(filePath, 0o600);
    } catch {
      // Best effort on platforms without POSIX permissions.
    }
  };

  const secretValues = {
    postgres_superuser_password: postgresSuper,
    app_db_password: appDbPassword,
    keycloak_db_password: keycloakDbPassword,
    redis_password: redisPassword,
    keycloak_admin_password: keycloakAdminPassword,
    nats_password: natsPassword,
    minio_root_password: minioRootPassword,
    mariadb_root_password: mariadbRootPassword,
    phpmyadmin_control_password: phpmyadminControlPassword,
    grafana_admin_password: grafanaAdminPassword,
    session_secret: sessionSecret,
    session_signing_keys: sessionSigningKeys,
    projects_gateway_signing_keys: projectsGatewaySigningKeys,
    hash_pepper_keys: hashPepperKeys,
    backup_signing_keys: backupSigningKeys,
    smtp_password: smtpPassword,
    google_oauth_client_secret: googleOAuthClientSecret,
    database_url: databaseUrl,
    nats_url: natsUrl,
  };

  for (const [name, value] of Object.entries(secretValues)) {
    writeSecretFile(name, value);
  }
  runSecretManager(["init", "--secretsDir", secretsDir, "--envFile", envFile]);

  if (sanitizeEnv && fs.existsSync(envFile)) {
    const sensitive = new Set([
      "POSTGRES_SUPERUSER_PASSWORD",
      "APP_DB_PASSWORD",
      "KEYCLOAK_DB_PASSWORD",
      "REDIS_PASSWORD",
      "KEYCLOAK_ADMIN_PASSWORD",
      "NATS_PASSWORD",
      "MINIO_ROOT_PASSWORD",
      "MARIADB_ROOT_PASSWORD",
      "PHPMYADMIN_CONTROL_PASSWORD",
      "GRAFANA_ADMIN_PASSWORD",
      "SESSION_SECRET",
      "SMTP_PASSWORD",
      "GOOGLE_OAUTH_CLIENT_SECRET",
    ]);
    const next = fs.readFileSync(envFile, "utf8").split(/\r?\n/).map((line) => {
      const key = line.split("=", 1)[0];
      return sensitive.has(key) ? `${key}=managed_by_local_secret_file` : line;
    }).join("\n");
    fs.writeFileSync(envFile, next, "utf8");
  }

  log(`Local secrets initialized in ${secretsDir}`);
  log("Stexor Secret Manager is the canonical encrypted local secret store.");
  log("Use compose.secrets.yaml when starting the local stack.");
}

async function localSecretManager() {
  await initLocalSecrets();
  await validateLocalSecrets();
  await signExistingPostgresBackups();
  log("Local secret manager is ready: Docker secret files are materialized from the encrypted local store, and PostgreSQL backups are signed.");
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
  };
}

function writeExternalUptimeReport({ manifestPath, providerEvidence, results, mode }) {
  const stamp = reportTimestamp();
  const payload = { generatedAt: new Date().toISOString(), mode, manifestPath, providerEvidence, results };
  const jsonPath = writeJsonReport("uptime", `external-uptime-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("uptime", `external-uptime-${stamp}`, [
    "# Stexor External Uptime Check",
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
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
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

function alertMetricScript({ requireEmailDelivery, requireDiscordDelivery, requireTelegramDelivery, timeoutMs }) {
  return `
const fs = require("node:fs");
const http = require("node:http");
const token = fs.readFileSync("/run/secrets/alertmanager_webhook_token", "utf8").trim();
const timeoutMs = ${JSON.stringify(timeoutMs)};
const required = ${JSON.stringify({ email: requireEmailDelivery, discord: requireDiscordDelivery, telegram: requireTelegramDelivery })};
function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : undefined;
    const req = http.request({
      method,
      hostname: "127.0.0.1",
      port: 3000,
      path,
      headers: {
        ...(data ? { "content-type": "application/json", "content-length": data.length } : {}),
        ...(method === "POST" ? { authorization: "Bearer " + token } : {}),
      },
      timeout: timeoutMs,
    }, (res) => {
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
function metric(text, name, labelText = "") {
  for (const line of text.split(/\\r?\\n/)) {
    if (!line.startsWith(name)) continue;
    if (labelText && !line.includes("{" + labelText + "}")) continue;
    const value = Number(line.trim().split(/\\s+/).at(-1));
    if (Number.isFinite(value)) return value;
  }
  return 0;
}
async function metrics() {
  const response = await request("GET", "/metrics");
  if (response.status !== 200) throw new Error("metrics status " + response.status);
  return response.text;
}
(async () => {
  const before = await metrics();
  const payload = {
    receiver: "stexor-synthetic",
    status: "firing",
    alerts: [{
      status: "firing",
      labels: {
        alertname: "StexorSyntheticAlertDeliveryTest",
        severity: "info",
        service: "stexor-platform",
        job: "alert-evidence",
      },
      annotations: {
        summary: "Synthetic Stexor alert delivery test",
        description: "Generated by alert-evidence to verify Alertmanager webhook delivery.",
      },
      startsAt: new Date().toISOString(),
    }],
  };
  const accepted = await request("POST", "/alerts/prometheus", payload);
  if (accepted.status !== 202) throw new Error("alert webhook status " + accepted.status + ": " + accepted.text);
  const start = Date.now();
  let after = "";
  while (Date.now() - start < timeoutMs) {
    after = await metrics();
    const webhookBefore = metric(before, "notification_alert_webhook_requests_total", 'service="enterprise-worker-notifications"');
    const webhookAfter = metric(after, "notification_alert_webhook_requests_total", 'service="enterprise-worker-notifications"');
    const firingBefore = metric(before, "notification_alert_webhook_alerts_total", 'service="enterprise-worker-notifications",status="firing"');
    const firingAfter = metric(after, "notification_alert_webhook_alerts_total", 'service="enterprise-worker-notifications",status="firing"');
    const emailOk = !required.email || metric(after, "notification_alert_email_deliveries_total", 'service="enterprise-worker-notifications"') > metric(before, "notification_alert_email_deliveries_total", 'service="enterprise-worker-notifications"');
    const discordOk = !required.discord || metric(after, "notification_alert_discord_deliveries_total", 'service="enterprise-worker-notifications"') > metric(before, "notification_alert_discord_deliveries_total", 'service="enterprise-worker-notifications"');
    const telegramOk = !required.telegram || metric(after, "notification_alert_telegram_deliveries_total", 'service="enterprise-worker-notifications"') > metric(before, "notification_alert_telegram_deliveries_total", 'service="enterprise-worker-notifications"');
    if (webhookAfter > webhookBefore && firingAfter > firingBefore && emailOk && discordOk && telegramOk) {
      console.log(JSON.stringify({ before, after, acceptedStatus: accepted.status }));
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("alert delivery counters did not increase before timeout");
})().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exit(1);
});
`;
}

async function alertEvidence(options = {}) {
  log("==> Alert delivery evidence");
  const sendTest = options.sendTest ?? booleanFlag(argv.sendTest);
  const enforce = options.enforce ?? booleanFlag(argv.enforce);
  const requireEmailDelivery = options.requireEmailDelivery ?? booleanFlag(argv.requireEmailDelivery);
  const requireDiscordDelivery = options.requireDiscordDelivery ?? booleanFlag(argv.requireDiscordDelivery);
  const requireTelegramDelivery = options.requireTelegramDelivery ?? booleanFlag(argv.requireTelegramDelivery);
  const requireSource = options.requireSource ?? booleanFlag(argv.requireSource ?? process.env.STEXOR_REQUIRE_SOURCE_ROOT);
  const timeoutMs = positiveInteger(options.timeoutMs ?? argv.timeoutMs ?? 15000, "--timeoutMs", 1000);
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const composeSecrets = readText(path.join(infraRoot, "compose.secrets.yaml"));
  const alertmanagerConfig = readText(path.join(infraRoot, "alertmanager", "alertmanager.yml"));
  const prometheusAlerts = readText(path.join(infraRoot, "prometheus", "rules", "enterprise-alerts.yml"));
  const workerNotificationsServerPath = path.join(sourceRoot, "apps", "worker-notifications", "src", "server.ts");
  const workerNotificationsServer = fs.existsSync(workerNotificationsServerPath) ? readText(workerNotificationsServerPath) : null;
  const issues = [];

  const checks = [
    ["alertmanager-webhook-target", /worker-notifications:3000\/alerts\/prometheus/.test(alertmanagerConfig)],
    ["alertmanager-bearer-token-secret", /credentials_file:\s+\/run\/secrets\/alertmanager_webhook_token/.test(alertmanagerConfig)],
    ["compose-alertmanager-secret-file", /ALERTMANAGER_WEBHOOK_TOKEN_FILE:\s+\/run\/secrets\/alertmanager_webhook_token/.test(composeSecrets)],
    ["compose-email-recipient", /ALERT_EMAIL_TO:\s+\$\{ALERT_EMAIL_TO/.test(compose)],
    ["compose-discord-secret-file", /ALERT_DISCORD_WEBHOOK_URL_FILE:\s+\$\{ALERT_DISCORD_WEBHOOK_URL_FILE:-\}/.test(compose)],
    ["compose-telegram-secret-file", /ALERT_TELEGRAM_BOT_TOKEN_FILE:\s+\$\{ALERT_TELEGRAM_BOT_TOKEN_FILE:-\}/.test(compose)],
    ["prometheus-delivery-failure-alert", /alert:\s+AlertmanagerDeliveryFailed/.test(prometheusAlerts)],
  ].map(([name, passed]) => ({ name, passed: Boolean(passed) }));

  if (workerNotificationsServer) {
    checks.push(
      { name: "worker-webhook-auth", passed: /ALERTMANAGER_WEBHOOK_TOKEN/.test(workerNotificationsServer) && /isAuthorizedAlertWebhook/.test(workerNotificationsServer) },
      { name: "worker-email-metrics", passed: /notification_alert_email_deliveries_total/.test(workerNotificationsServer) && /notification_alert_email_failures_total/.test(workerNotificationsServer) },
      { name: "worker-discord-metrics", passed: /notification_alert_discord_deliveries_total/.test(workerNotificationsServer) && /notification_alert_discord_failures_total/.test(workerNotificationsServer) },
      { name: "worker-telegram-metrics", passed: /notification_alert_telegram_deliveries_total/.test(workerNotificationsServer) && /notification_alert_telegram_failures_total/.test(workerNotificationsServer) },
    );
  } else {
    checks.push({
      name: "worker-source-checks",
      passed: !requireSource,
      skipped: !requireSource,
      detail: `Optional Stexor source not mounted at ${workerNotificationsServerPath}`,
    });
    if (requireSource) {
      issues.push(`Required Stexor source file is missing: ${workerNotificationsServerPath}`);
    }
  }

  for (const check of checks) {
    if (!check.passed) issues.push(`Alert evidence check failed: ${check.name}`);
  }

  let runtime = null;
  if (sendTest) {
    const inspect = run("docker", ["inspect", "--format", "{{.State.Status}}", "enterprise-worker-notifications"], { capture: true, allowFailure: true });
    if (inspect.status !== 0 || String(inspect.stdout ?? "").trim() !== "running") {
      fail("enterprise-worker-notifications must be running for --sendTest.");
    }
    const script = alertMetricScript({ requireEmailDelivery, requireDiscordDelivery, requireTelegramDelivery, timeoutMs });
    const result = dockerExec("enterprise-worker-notifications", ["node", "-e", script], { capture: true });
    runtime = JSON.parse(String(result.stdout ?? "").trim().split(/\r?\n/).at(-1));
  } else {
    issues.push("Synthetic runtime alert was not sent. Re-run with --sendTest in local/staging/VPS.");
  }

  const payload = {
    generatedAt: new Date().toISOString(),
    mode: sendTest ? "send-test" : "summary",
    status: issues.length ? "warning" : "passed",
    checks,
    runtime,
    source: {
      required: requireSource,
      available: Boolean(workerNotificationsServer),
      workerNotificationsServerPath,
    },
    requestedDelivery: {
      email: requireEmailDelivery,
      discord: requireDiscordDelivery,
      telegram: requireTelegramDelivery,
    },
    issues,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("alerts", `alert-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("alerts", `alert-evidence-${stamp}`, [
    "# Stexor Alert Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    "",
    "| Check | Passed |",
    "| --- | --- |",
    ...checks.map((check) => `| ${check.name} | ${check.skipped ? "skipped" : check.passed ? "yes" : "no"} |`),
    "",
    "## Source",
    "",
    `Stexor source required: ${requireSource ? "yes" : "no"}`,
    `Stexor source available: ${workerNotificationsServer ? "yes" : "no"}`,
    `Worker source path: ${workerNotificationsServerPath}`,
    "",
    "## Runtime Delivery",
    "",
    `Synthetic alert sent: ${sendTest ? "yes" : "no"}`,
    `Email delivery required: ${requireEmailDelivery ? "yes" : "no"}`,
    `Discord delivery required: ${requireDiscordDelivery ? "yes" : "no"}`,
    `Telegram delivery required: ${requireTelegramDelivery ? "yes" : "no"}`,
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- None"]),
  ]);
  log(`Alert evidence written to ${jsonPath} and ${markdownPath}`);
  if (enforce && issues.length) {
    fail(`Alert evidence enforcement failed with ${issues.length} issue(s). Reports: ${jsonPath}, ${markdownPath}`);
  }
  return payload;
}

async function loadSmoke() {
  const requests = positiveInteger(argv.requests ?? 80, "requests");
  const concurrency = positiveInteger(argv.concurrency ?? 8, "concurrency");
  const maxP95Ms = Number(argv.maxP95Ms ?? 750);
  if (!argv.url && !booleanFlag(argv.edge)) {
    runInternalBackendLoadProbe({ label: "Internal backend load smoke", requests, concurrency, maxP95Ms });
    return;
  }
  const url = argv.url ?? "https://api.localhost.com/health";
  await runLoadProbe({ label: "Load smoke", url, requests, concurrency, maxP95Ms });
}

async function loadProfile() {
  const durationSeconds = positiveInteger(argv.durationSeconds ?? 60, "durationSeconds");
  const targetRps = positiveInteger(argv.targetRps ?? 8, "targetRps");
  const concurrency = positiveInteger(argv.concurrency ?? Math.max(4, Math.min(64, targetRps)), "concurrency");
  const requests = positiveInteger(argv.requests ?? durationSeconds * targetRps, "requests");
  const maxP95Ms = Number(argv.maxP95Ms ?? 1000);
  if (!argv.url && !booleanFlag(argv.edge)) {
    runInternalBackendLoadProbe({ label: "Sustained internal backend load profile", requests, concurrency, maxP95Ms });
    return;
  }
  const url = argv.url ?? "https://api.localhost.com/health";
  await runLoadProbe({ label: "Sustained load profile", url, requests, concurrency, maxP95Ms });
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

async function loadTargetEvidence({ url, mode, requirePublicTarget, requireEdgeEvidence, expectedEdgeProvider, timeoutMs }) {
  if (mode === "internal") {
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
  if (requirePublicTarget && !publicTarget) {
    fail(`Load benchmark production target must be public, not ${url}.`);
  }

  const started = performance.now();
  const response = await request("GET", url, { timeoutMs });
  const latencyMs = Math.round(performance.now() - started);
  const edgeProvider = detectEdgeProvider(response.headers);
  const providerMatched = expectedEdgeProvider === "any"
    ? Boolean(edgeProvider)
    : expectedEdgeProvider === "none"
      ? true
      : edgeProvider === expectedEdgeProvider;
  if (requireEdgeEvidence && !providerMatched) {
    fail(`Load benchmark edge evidence missing or mismatched: expected=${expectedEdgeProvider}, observed=${edgeProvider ?? "none"}.`);
  }

  return {
    mode,
    url,
    protocol: parsed.protocol.replace(/:$/, ""),
    hostname: parsed.hostname,
    public: publicTarget,
    publicRequired: requirePublicTarget,
    edgeRequired: requireEdgeEvidence,
    edge: {
      status: response.status,
      latencyMs,
      provider: edgeProvider,
      expectedProvider: expectedEdgeProvider,
      providerMatched,
      headers: selectedEdgeHeaders(response.headers),
    },
  };
}

function writeLoadBenchmarkReport(payload) {
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("load", `load-benchmark-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("load", `load-benchmark-${stamp}`, [
    "# Stexor Load Benchmark",
    "",
    `Generated at: ${payload.generatedAt}`,
    `Status: ${payload.status}`,
    `Target: ${payload.url}`,
    `Target public: ${payload.target?.public ? "yes" : "no"}`,
    `Edge provider: ${payload.target?.edge?.provider ?? "n/a"}`,
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
  const targetUrl = useEdge ? url : "container:enterprise-backend/health";
  const requirePublicTarget = booleanFlag(argv.requirePublicTarget);
  const requireEdgeEvidence = booleanFlag(argv.requireEdgeEvidence);
  const expectedEdgeProvider = String(argv.expectedEdgeProvider ?? "cloudflare").toLowerCase();
  const preflightTimeoutMs = positiveInteger(argv.preflightTimeoutMs ?? 10000, "preflightTimeoutMs", 1000);
  const issues = [];
  let target = null;
  log("==> Load benchmark");
  try {
    target = await loadTargetEvidence({
      url: targetUrl,
      mode: useEdge ? "edge" : "internal",
      requirePublicTarget,
      requireEdgeEvidence,
      expectedEdgeProvider,
      timeoutMs: preflightTimeoutMs,
    });
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
          ? runInternalBackendLoadProbe({ label: `Internal load benchmark ${users} users`, requests, concurrency, maxP95Ms })
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

  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : "passed",
    url: targetUrl,
    target,
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

function runInternalBackendLoadProbe({ label, requests, concurrency, maxP95Ms }) {
  const script = `
const http = require("node:http");
const { performance } = require("node:perf_hooks");
const requests = ${JSON.stringify(requests)};
const concurrency = ${JSON.stringify(concurrency)};
const maxP95Ms = ${JSON.stringify(maxP95Ms)};
const latencies = [];
const errors = [];
let nextRequest = 0;
function once() {
  return new Promise((resolve) => {
    const started = performance.now();
    const req = http.request({ method: "GET", hostname: "127.0.0.1", port: 3000, path: "/health" }, (res) => {
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
    nextRequest += 1;
    await once();
  }
}
Promise.all(Array.from({ length: Math.min(concurrency, requests) }, () => worker())).then(() => {
  const sorted = latencies.sort((a, b) => a - b);
  const p95Index = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * 0.95) - 1));
  const p95 = sorted[p95Index] ?? 0;
  const avg = sorted.reduce((sum, value) => sum + value, 0) / Math.max(sorted.length, 1);
  console.log(JSON.stringify({ errors, requests, concurrency, avg, p95, maxP95Ms }));
  process.exit(errors.length || p95 > maxP95Ms ? 1 : 0);
});
`;
  const result = dockerExec("enterprise-backend", ["node", "-e", script], { capture: true, allowFailure: true });
  const text = String(result.stdout ?? "").trim();
  const parsed = text ? JSON.parse(text.split(/\r?\n/).at(-1)) : null;
  if (!parsed) {
    fail(`${label} did not return metrics.`);
  }
  if (result.status !== 0) {
    if (parsed.errors?.length) parsed.errors.slice(0, 10).forEach((error) => log(`internal backend returned ${error}`));
    fail(`${label} failed: errors=${parsed.errors?.length ?? 0} p95=${parsed.p95}ms maxP95Ms=${parsed.maxP95Ms}ms.`);
  }
  log(`${label} passed: requests=${parsed.requests} requestedConcurrency=${parsed.concurrency} avg=${parsed.avg.toFixed(2)}ms p95=${parsed.p95}ms`);
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

const resticPassthroughEnvKeys = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_DEFAULT_REGION",
  "RESTIC_AWS_ASSUME_ROLE_ARN",
  "RESTIC_AWS_ASSUME_ROLE_SESSION_NAME",
  "RESTIC_AWS_ASSUME_ROLE_EXTERNAL_ID",
  "RESTIC_AWS_ASSUME_ROLE_REGION",
  "RESTIC_AWS_ASSUME_ROLE_STS_ENDPOINT",
  "B2_ACCOUNT_ID",
  "B2_ACCOUNT_KEY",
  "AZURE_ACCOUNT_NAME",
  "AZURE_ACCOUNT_KEY",
  "AZURE_ACCOUNT_SAS",
  "AZURE_ENDPOINT_SUFFIX",
  "GOOGLE_PROJECT_ID",
  "GOOGLE_ACCESS_TOKEN",
  "OS_AUTH_URL",
  "OS_REGION_NAME",
  "OS_USERNAME",
  "OS_USER_ID",
  "OS_PASSWORD",
  "OS_TENANT_ID",
  "OS_TENANT_NAME",
  "OS_USER_DOMAIN_NAME",
  "OS_USER_DOMAIN_ID",
  "OS_PROJECT_NAME",
  "OS_PROJECT_DOMAIN_NAME",
];

function resticConfig(options = {}) {
  const repository = options.repository ?? argv.repository ?? process.env.RESTIC_REPOSITORY;
  const passwordFile = path.resolve(options.passwordFile ?? argv.passwordFile ?? process.env.RESTIC_PASSWORD_FILE ?? path.join(infraRoot, "secrets", "restic_password.txt"));
  const tag = options.tag ?? argv.tag ?? "stexor-backups";
  return { repository, passwordFile, tag };
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

function resticDockerContainerArgs({ repository, passwordFile, mounts = [] }) {
  const resticPasswordDir = path.dirname(passwordFile);
  const resticPasswordName = path.basename(passwordFile);
  const args = [
    "run",
    "--rm",
    "-e",
    `RESTIC_REPOSITORY=${repository}`,
    "-e",
    `RESTIC_PASSWORD_FILE=/restic-password/${resticPasswordName}`,
  ];
  for (const key of resticPassthroughEnvKeys) {
    if (process.env[key]) {
      args.push("-e", key);
    }
  }
  args.push(
    ...mounts,
    "-v",
    `${hostPathForContainerMount(resticPasswordDir)}:/restic-password:ro`,
    "restic/restic:0.18.0",
  );
  return args;
}

function resticDockerRun({ repository, passwordFile, mounts = [], resticArgs = [], runOptions = {} }) {
  return run("docker", [
    ...resticDockerContainerArgs({ repository, passwordFile, mounts }),
    ...resticArgs,
  ], runOptions);
}

async function offsiteBackupRestic() {
  const backupFile = argv.backupFile ? path.resolve(argv.backupFile) : null;
  const { repository, passwordFile, tag } = resticConfig();
  requireResticCredentials({ repository, passwordFile });
  const backupRoot = path.join(infraRoot, "backups");
  const backupName = backupFile ? path.basename(backupFile) : null;
  let mountSource = backupRoot;
  let mountTarget = "/backups";
  let resticPaths = [];
  let artifactLabels = [];

  if (backupFile) {
    if (!fs.existsSync(backupFile)) {
      fail(`Backup file not found: ${backupFile}`);
    }
    verifyBackupArtifact(backupFile);
    mountSource = path.dirname(backupFile);
    mountTarget = "/backup";
    const sidecars = [`${backupName}.sha256`, `${backupName}.sig.json`].filter((file) => fs.existsSync(path.join(mountSource, file)));
    resticPaths = [`/backup/${backupName}`, ...sidecars.map((file) => `/backup/${file}`)];
    artifactLabels = [backupFile];
  } else {
    const specs = [
      ["postgres", path.join(backupRoot, "postgres"), (file) => file.endsWith(".dump")],
      ["mariadb", path.join(backupRoot, "mariadb"), (file) => file.endsWith(".sql.gz")],
      ["minio", path.join(backupRoot, "minio"), (file) => file.endsWith(".tar.gz")],
      ["keycloak", path.join(backupRoot, "keycloak"), (file) => file.endsWith(".tar.gz")],
      ["secret-manager", path.join(backupRoot, "secret-manager"), (file) => file.endsWith(".tar.gz")],
    ];
    const missing = [];
    const artifacts = [];
    for (const [label, directory, predicate] of specs) {
      const artifact = latestFileByMtime(directory, predicate);
      if (!artifact) {
        missing.push(label);
        continue;
      }
      verifyBackupArtifact(artifact);
      artifacts.push(artifact);
    }
    if (missing.length && !booleanFlag(argv.allowPartial)) {
      fail(`Missing local backup artifacts for off-site upload: ${missing.join(", ")}. Run the matching backup-* command first or pass --allowPartial.`);
    }
    if (!artifacts.length) {
      fail("No local backup artifacts found. Run backup-postgres, backup-mariadb, backup-minio, backup-keycloak and backup-secret-manager-metadata first.");
    }
    const pathSet = new Set();
    for (const artifact of artifacts) {
      const sidecars = [`${artifact}.sha256`, `${artifact}.sig.json`].filter((file) => fs.existsSync(file));
      for (const filePath of [artifact, ...sidecars]) {
        const relative = path.relative(backupRoot, filePath).replaceAll("\\", "/");
        pathSet.add(`/backups/${relative}`);
      }
    }
    resticPaths = [...pathSet];
    artifactLabels = artifacts;
  }
  resticDockerRun({
    repository,
    passwordFile,
    mounts: ["-v", `${hostPathForContainerMount(mountSource)}:${mountTarget}:ro`],
    resticArgs: ["backup", ...resticPaths, "--tag", tag],
  });
  log(`Off-site backup completed for ${artifactLabels.join(", ")}`);
}

const offsiteRestoreFamilySpecs = [
  {
    key: "postgres",
    label: "PostgreSQL",
    backupDirectory: "postgres",
    predicate: (filePath) => filePath.endsWith(".dump"),
    restore: (options) => restoreTestPostgres(options),
  },
  {
    key: "mariadb",
    label: "MariaDB",
    backupDirectory: "mariadb",
    predicate: (filePath) => filePath.endsWith(".sql.gz"),
    restore: (options) => restoreTestMariadb(options),
  },
  {
    key: "minio",
    label: "MinIO",
    backupDirectory: "minio",
    predicate: (filePath) => /minio-data-.+\.tar\.gz$/.test(path.basename(filePath)),
    restore: (options) => restoreTestMinio(options),
  },
  {
    key: "keycloak",
    label: "Keycloak",
    backupDirectory: "keycloak",
    predicate: (filePath) => /keycloak-config-.+\.tar\.gz$/.test(path.basename(filePath)),
    restore: (options) => restoreTestKeycloakConfig(options),
  },
  {
    key: "secret-manager-metadata",
    label: "Secret Manager metadata",
    backupDirectory: "secret-manager",
    predicate: (filePath) => /secret-manager-metadata-.+\.tar\.gz$/.test(path.basename(filePath)),
    restore: (options) => restoreTestSecretManagerMetadata(options),
  },
];

function offsiteRestoreFamilies(value) {
  const aliases = new Map();
  for (const spec of offsiteRestoreFamilySpecs) {
    aliases.set(spec.key, spec);
  }
  aliases.set("secret-manager", offsiteRestoreFamilySpecs.find((spec) => spec.key === "secret-manager-metadata"));
  const rawFamilies = value
    ? (Array.isArray(value) ? value : String(value).split(","))
    : offsiteRestoreFamilySpecs.map((spec) => spec.key);
  const selected = [];
  const seen = new Set();
  for (const raw of rawFamilies.map((item) => String(item).trim()).filter(Boolean)) {
    const spec = aliases.get(raw);
    if (!spec) {
      fail(`Unknown off-site restore family '${raw}'. Use one of: ${offsiteRestoreFamilySpecs.map((item) => item.key).join(", ")}.`);
    }
    if (!seen.has(spec.key)) {
      selected.push(spec);
      seen.add(spec.key);
    }
  }
  if (!selected.length) {
    fail("At least one off-site restore family is required.");
  }
  return selected;
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

function discoverRestoredBackupArtifacts(restoreRoot, families) {
  const restoredFiles = listFilesRecursive(restoreRoot);
  const discovered = {};
  for (const family of families) {
    discovered[family.key] = restoredFiles.find((filePath) => family.predicate(filePath)) ?? null;
  }
  return discovered;
}

function stageRestoredBackupArtifact({ sourceFile, family, stagingRoot }) {
  const targetDir = path.join(stagingRoot, family.backupDirectory);
  fs.mkdirSync(targetDir, { recursive: true });
  const stagedArtifact = assertPathInside(targetDir, path.join(targetDir, path.basename(sourceFile)));
  fs.copyFileSync(sourceFile, stagedArtifact);
  const copiedSidecars = [];
  for (const sidecar of [`${sourceFile}.sha256`, `${sourceFile}.sig.json`]) {
    if (!fs.existsSync(sidecar)) {
      continue;
    }
    const stagedSidecar = assertPathInside(targetDir, path.join(targetDir, path.basename(sidecar)));
    fs.copyFileSync(sidecar, stagedSidecar);
    copiedSidecars.push(stagedSidecar);
  }
  const { hash, keyId, signaturePath } = verifyBackupArtifact(stagedArtifact);
  return { stagedArtifact, copiedSidecars, hash, keyId, signaturePath };
}

function offsiteRestoreCoverage(payload = {}) {
  const requiredFamilies = offsiteRestoreFamilySpecs.map((family) => family.key);
  const requestedFamilies = Array.isArray(payload.families) ? payload.families : [];
  const successfulFamilies = [...new Set((payload.steps ?? [])
    .filter((step) => step.family && step.status === "success")
    .map((step) => step.family))];
  const missingRequiredFamilies = requiredFamilies.filter((family) => !successfulFamilies.includes(family));
  const unrequestedRequiredFamilies = requiredFamilies.filter((family) => !requestedFamilies.includes(family));
  const infraHealthOk = (payload.steps ?? []).some((step) => step.name === "infra-health" && step.status === "success");
  const complete = payload.mode === "restore"
    && payload.status === "success"
    && payload.allowPartial !== true
    && missingRequiredFamilies.length === 0
    && unrequestedRequiredFamilies.length === 0
    && infraHealthOk;
  return {
    requiredFamilies,
    requestedFamilies,
    successfulFamilies,
    missingRequiredFamilies,
    unrequestedRequiredFamilies,
    allowPartial: payload.allowPartial === true,
    infraHealthOk,
    complete,
  };
}

function writeOffsiteRestoreDrillReport(payload) {
  const stamp = reportTimestamp();
  const baseName = `offsite-restore-drill-${payload.mode}-${stamp}-${crypto.randomBytes(3).toString("hex")}`;
  const reportPayload = {
    ...payload,
    coverage: payload.coverage ?? offsiteRestoreCoverage(payload),
  };
  const jsonPath = writeJsonReport("offsite-restore-drills", baseName, reportPayload);
  const rows = (reportPayload.steps ?? []).map((step) => `| ${step.family ?? step.name} | ${step.status} | ${step.durationMs ?? "n/a"} | ${step.artifactName ?? "n/a"} |`);
  const markdownPath = writeMarkdownReport("offsite-restore-drills", baseName, [
    "# Stexor Off-site Restore Drill",
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
    `Successful families: ${reportPayload.coverage.successfulFamilies.join(", ") || "none"}`,
    `Missing required families: ${reportPayload.coverage.missingRequiredFamilies.join(", ") || "none"}`,
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
  const families = offsiteRestoreFamilies(options.families ?? argv.families);
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
    families: families.map((family) => family.key),
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
    steps: [],
  };

  if (planOnly) {
    const finishedAt = new Date();
    const payload = {
      ...basePayload,
      status: "success",
      finishedAt: finishedAt.toISOString(),
      durationMs: finishedAt.getTime() - startedAt.getTime(),
      steps: families.map((family) => ({
        family: family.key,
        status: "planned",
        artifactName: `${family.backupDirectory}/latest signed artifact`,
      })),
      notes: [
        "Use --dryRun to validate the remote Restic repository and selected snapshot without restoring files.",
        "Run without --dryRun to restore into disposable local paths and execute restore-test commands.",
      ],
    };
    writeOffsiteRestoreDrillReport(payload);
    log(`Off-site restore drill plan generated for families: ${payload.families.join(", ")}`);
    return payload;
  }

  requireResticCredentials({ repository, passwordFile });

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
    payload = {
      ...payload,
      snapshot: resticSnapshotSummary(snapshot),
      snapshotCountForTag: snapshots.length,
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
        status: "success",
        finishedAt: finishedAt.toISOString(),
        durationMs: finishedAt.getTime() - startedAt.getTime(),
        steps: [{
          name: "restic-restore-dry-run",
          status: "success",
          durationMs: finishedAt.getTime() - startedAt.getTime(),
          artifactName: "remote snapshot",
        }],
        resticOutputPreview: String(dryRunResult.stdout ?? dryRunResult.stderr ?? "").slice(0, 12000),
      };
      writeOffsiteRestoreDrillReport(payload);
      log(`Off-site Restic dry-run passed for snapshot ${snapshot.short_id ?? snapshot.id ?? snapshotId}.`);
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

    const discovered = discoverRestoredBackupArtifacts(restoreRoot, families);
    const missing = families.filter((family) => !discovered[family.key]).map((family) => family.key);
    if (missing.length && !allowPartial) {
      fail(`Remote Restic restore did not contain required backup artifacts: ${missing.join(", ")}. Pass --allowPartial only for bootstrap validation.`);
    }

    for (const family of families) {
      const sourceFile = discovered[family.key];
      if (!sourceFile) {
        payload.steps.push({ family: family.key, status: "missing", artifactName: "n/a" });
        continue;
      }
      const staged = stageRestoredBackupArtifact({ sourceFile, family, stagingRoot });
      const stepStarted = Date.now();
      const result = await family.restore({ backupFile: staged.stagedArtifact });
      payload.steps.push({
        family: family.key,
        label: family.label,
        status: "success",
        durationMs: Date.now() - stepStarted,
        artifactName: path.basename(staged.stagedArtifact),
        stagedArtifact: staged.stagedArtifact,
        sha256: staged.hash,
        signatureKeyId: staged.keyId,
        signaturePath: staged.signaturePath,
        result,
      });
    }

    if (!payload.steps.some((step) => step.status === "success")) {
      fail("No restored off-site artifacts were tested.");
    }

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
    log(`Off-site restore drill completed for families: ${families.map((family) => family.key).join(", ")}`);
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
  if (!fs.existsSync(envFile)) {
    fail(`Env file not found: ${envFile}`);
  }
  const env = parseEnv(envFile);
  const requireKey = (key) => {
    if (!env[key]) {
      fail(`Missing required production env: ${key}`);
    }
    if (/change_me|your-domain|localhost/i.test(env[key])) {
      fail(`Production env ${key} still contains placeholder/local value: ${env[key]}`);
    }
  };
  [
    "TRAEFIK_ACME_EMAIL",
    "API_PUBLIC_URL",
    "ACCOUNT_PUBLIC_URL",
    "UI_PUBLIC_URL",
    "NEXT_PUBLIC_API_URL",
    "NEXT_PUBLIC_UI_URL",
    "NEXT_PUBLIC_ACCOUNT_URL",
    "NEXTAUTH_URL",
    "KEYCLOAK_ISSUER",
    "WEBAUTHN_RP_ID",
    "WEBAUTHN_ORIGINS",
    "CORS_ORIGINS",
    "SMTP_USER",
    "BACKEND_IMAGE",
    "WEB_IMAGE",
    "WORKER_NOTIFICATIONS_IMAGE",
    "WORKER_JOBS_IMAGE",
  ].forEach(requireKey);

  for (const [key, minLength] of [
    ["SESSION_SECRET", 48],
    ["SESSION_SIGNING_KEYS", 48],
    ["SECRET_HASH_KEYS", 48],
    ["BACKUP_SIGNING_KEYS", 48],
    ["POSTGRES_SUPERUSER_PASSWORD", 24],
    ["APP_DB_PASSWORD", 24],
    ["KEYCLOAK_DB_PASSWORD", 24],
    ["REDIS_PASSWORD", 24],
    ["NATS_PASSWORD", 24],
    ["MINIO_ROOT_PASSWORD", 24],
    ["GRAFANA_ADMIN_PASSWORD", 24],
    ["SMTP_PASSWORD", 16],
  ]) {
    requireManagedSecret(env, key);
  }

  for (const imageKey of ["BACKEND_IMAGE", "WEB_IMAGE", "WORKER_NOTIFICATIONS_IMAGE", "WORKER_JOBS_IMAGE"]) {
    if (/:latest(?:@|$)/.test(env[imageKey])) {
      fail(`${imageKey} must use an immutable version tag and digest, not :latest`);
    }
    if (!/@sha256:[a-f0-9]{64}$/i.test(env[imageKey])) {
      fail(`${imageKey} must be pinned by digest.`);
    }
    if (/@sha256:0{64}$/i.test(env[imageKey])) {
      fail(`${imageKey} must use a real image digest, not the all-zero placeholder.`);
    }
  }
  if ((env.SESSION_COOKIE_SECURE ?? "true").toLowerCase() !== "true") {
    fail("SESSION_COOKIE_SECURE must be true in production.");
  }
  if (hasManagedSecret(env, "SESSION_SECRET") && !env.SECRET_MANAGER_PROVIDER) {
    fail("Managed production secrets require SECRET_MANAGER_PROVIDER.");
  }
  if (!argv.skipDns) {
    for (const host of [env.UI_HOST, env.ACCOUNT_HOST, env.API_HOST, env.AUTH_HOST].filter(Boolean)) {
      if (/localhost|your-domain/i.test(host)) {
        fail(`Production host is not public: ${host}`);
      }
      await dns.resolve4(host);
    }
  }
  log("Production preflight passed.");
}

async function haConfigCheck() {
  log("==> HA multi-node configuration check");
  const haCompose = readText(path.join(infraRoot, "compose.ha.yaml"));
  for (const service of ["backend", "web", "worker-notifications", "worker-jobs"]) {
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?container_name:\\s*!reset null`, "m"), `${service} must reset fixed container_name for replicas.`);
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?replicas:\\s*\\$\\{`, "m"), `${service} must declare configurable replicas.`);
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?failure_action:\\s*rollback`, "m"), `${service} must rollback failed rolling updates.`);
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?rollback_config:`, "m"), `${service} must define rollback_config.`);
  }
  for (const service of ["postgres", "redis", "nats", "minio"]) {
    assertMatch(haCompose, new RegExp(`^\\s{2}${service}:[\\s\\S]*?node\\.labels\\.stexor\\.stateful == true`, "m"), `${service} must be pinned to stateful nodes or replaced by a managed tier.`);
  }
  run("docker", [
    "compose",
    "--env-file",
    ".env",
    "-p",
    "enterprise_prod_ha",
    "-f",
    "compose.yaml",
    "-f",
    "compose.prod.yaml",
    "-f",
    "compose.ha.yaml",
    "config",
    "--quiet",
  ]);
  log("HA multi-node configuration check passed.");
}

async function managedSecretsPreflight() {
  log("==> Managed secrets / KMS preflight");
  const managedCompose = readText(path.join(infraRoot, "compose.managed-secrets.yaml"));
  for (const secretName of [
    "postgres_superuser_password",
    "app_db_password",
    "keycloak_db_password",
    "redis_password",
    "keycloak_admin_password",
    "nats_password",
    "minio_root_password",
    "mariadb_root_password",
    "phpmyadmin_control_password",
    "grafana_admin_password",
    "session_secret",
    "session_signing_keys",
    "projects_gateway_signing_keys",
    "hash_pepper_keys",
    "backup_signing_keys",
    "smtp_password",
    "google_recaptcha_secret_key",
    "cloudflare_turnstile_secret_key",
    "google_oauth_client_secret",
    "database_url",
    "nats_url",
  ]) {
    assertMatch(managedCompose, new RegExp(`^\\s{2}${secretName}:\\s*\\r?\\n\\s+external:\\s+true`, "m"), `${secretName} must be declared as an external Docker secret.`);
  }
  for (const fileEnv of ["SESSION_SECRET_FILE", "SESSION_SIGNING_KEYS_FILE", "PROJECTS_GATEWAY_SIGNING_KEYS_FILE", "SECRET_HASH_KEYS_FILE", "DATABASE_URL_FILE", "SMTP_PASSWORD_FILE", "GOOGLE_RECAPTCHA_SECRET_KEY_FILE", "CLOUDFLARE_TURNSTILE_SECRET_KEY_FILE", "GOOGLE_OAUTH_CLIENT_SECRET_FILE"]) {
    assertMatch(managedCompose, new RegExp(`${fileEnv}:\\s+/run/secrets/`), `${fileEnv} must point at /run/secrets.`);
  }
  run("docker", [
    "compose",
    "--env-file",
    ".env",
    "-p",
    "enterprise_prod_managed_secrets",
    "-f",
    "compose.yaml",
    "-f",
    "compose.prod.yaml",
    "-f",
    "compose.managed-secrets.yaml",
    "config",
    "--quiet",
  ]);
  log("Managed secrets / KMS preflight passed.");
}

const managedSecretRotationExpectations = [
  { name: "postgres_superuser_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "app_db_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "keycloak_db_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "redis_password", kind: "opaque", rotationDays: 90 },
  { name: "keycloak_admin_password", kind: "opaque", rotationDays: 90 },
  { name: "nats_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "minio_root_password", kind: "opaque", rotationDays: 90 },
  { name: "mariadb_root_password", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "phpmyadmin_control_password", kind: "opaque", rotationDays: 90 },
  { name: "grafana_admin_password", kind: "opaque", rotationDays: 90 },
  { name: "session_secret", kind: "opaque", rotationDays: 90 },
  { name: "session_signing_keys", kind: "keyring", rotationDays: 60 },
  { name: "projects_gateway_signing_keys", kind: "keyring", rotationDays: 90 },
  { name: "hash_pepper_keys", kind: "keyring", rotationDays: 90 },
  { name: "backup_signing_keys", kind: "keyring", rotationDays: 90 },
  { name: "alertmanager_webhook_token", kind: "opaque", rotationDays: 90 },
  { name: "smtp_password", kind: "opaque", rotationDays: 90 },
  { name: "google_recaptcha_secret_key", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "cloudflare_turnstile_secret_key", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "google_oauth_client_secret", kind: "opaque", rotationDays: 90, manualRotation: true },
  { name: "database_url", kind: "derived", rotationDays: 90 },
  { name: "nats_url", kind: "derived", rotationDays: 90 },
];

function readJsonLines(filePath) {
  if (!fs.existsSync(filePath)) {
    return { entries: [], invalidLines: 0 };
  }
  const entries = [];
  let invalidLines = 0;
  for (const line of readText(filePath).split(/\r?\n/)) {
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
  const storePath = path.resolve(options.store ?? argv.store ?? path.join(secretsDir, "stexor-secret-manager-store.json"));
  const auditLogPath = path.resolve(options.auditLog ?? argv.auditLog ?? path.join(secretsDir, "stexor-secret-manager-audit.log"));
  const maxKmsAgeDays = optionalPositiveNumber(options.maxKmsAgeDays ?? argv.maxKmsAgeDays, "--maxKmsAgeDays", 180);
  const rotationGraceDays = optionalPositiveNumber(options.rotationGraceDays ?? argv.rotationGraceDays, "--rotationGraceDays", 0);
  const generatedAt = new Date().toISOString();
  const issues = [];
  const secretReports = [];
  let store = null;
  let verify = { status: "not-run", detail: "store missing" };

  if (!fs.existsSync(storePath)) {
    if (enforce) {
      issues.push(`missing Stexor Secret Manager store: ${storePath}`);
    }
  } else {
    try {
      store = readJsonFile(storePath, storePath);
    } catch (error) {
      issues.push(`secret manager store is unreadable: ${String(error?.message ?? error)}`);
    }
  }

  if (store) {
    if (store.manager !== "stexor-secret-manager" || store.version !== 1) {
      issues.push("secret manager store has an invalid manager/version marker");
    }
    if (store.kms?.provider !== "stexor-local-kms" || !store.kms?.activeKeyId) {
      issues.push("secret manager store is missing active Stexor Local KMS metadata");
    }
    const activeKmsKey = store.kms?.keys?.[store.kms?.activeKeyId];
    const activeKmsAgeDays = ageDaysFromIso(activeKmsKey?.createdAt);
    if (!Number.isFinite(activeKmsAgeDays)) {
      issues.push("active KMS key is missing a valid createdAt timestamp");
    } else if (activeKmsAgeDays > maxKmsAgeDays) {
      issues.push(`active KMS key is ${activeKmsAgeDays.toFixed(1)}d old; max ${maxKmsAgeDays}d`);
    }

    const storeSecrets = store.secrets ?? {};
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
        kind: record.kind ?? expected.kind,
        status,
        updatedAt: record.updatedAt ?? null,
        ageDays: Number.isFinite(ageDays) ? Number(ageDays.toFixed(3)) : null,
        rotationDays,
        rotationGraceDays,
        expired,
        manualRotation: Boolean(expected.manualRotation),
        materializedPresent,
        fingerprintPresent: Boolean(record.fingerprint),
        kmsKeyId: record.encryption?.keyId ?? null,
        keyIds: Array.isArray(record.keyIds) ? record.keyIds : [],
      });
    }

    const expectedNames = new Set(managedSecretRotationExpectations.map((secret) => secret.name));
    const unmanagedNames = Object.keys(storeSecrets).filter((name) => !expectedNames.has(name)).sort();
    if (unmanagedNames.length) {
      issues.push(`unexpected managed secret records: ${unmanagedNames.join(", ")}`);
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
      issues.push("stexor-secret-manager verify failed");
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
      expiredSecrets: expiredSecrets.length,
      missingMaterializedFiles: secretReports.filter((secret) => !secret.materializedPresent).length,
      manualRotationSecrets: secretReports.filter((secret) => secret.manualRotation).length,
      maxKmsAgeDays,
      rotationGraceDays,
    },
    secrets: secretReports,
    issues,
    nextCommands: [
      "sh ./scripts/stexor-secret-manager.sh init",
      "sh ./scripts/stexor-secret-manager.sh verify",
      "sh ./scripts/stexor-secret-manager.sh rotate --name session_signing_keys",
      "sh ./scripts/stexor-secret-manager.sh kms-rotate",
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
    "| Secret | Status | Kind | Age days | Rotation days | Materialized |",
    "| --- | --- | --- | ---: | ---: | --- |",
    ...(secretReports.length
      ? secretReports.map((secret) => `| ${secret.name} | ${secret.status} | ${secret.kind} | ${secret.ageDays ?? "n/a"} | ${secret.rotationDays ?? "n/a"} | ${secret.materializedPresent ? "yes" : "no"} |`)
      : ["| n/a | plan | n/a | n/a | n/a | no |"]),
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

async function releaseArtifactGate() {
  log("==> Release artifact admission gate");
  const env = parseEnv(path.resolve(argv.envFile ?? path.join(infraRoot, ".env")));
  const images = (argv.images ? argv.images.split(",") : releaseImageKeys.map((key) => env[key])).filter(Boolean);
  if (!images.length) {
    fail("No release images found. Set BACKEND_IMAGE, WEB_IMAGE, WORKER_NOTIFICATIONS_IMAGE and WORKER_JOBS_IMAGE or pass --images.");
  }
  for (const image of images) {
    if (/:latest(?:@|$)/.test(image)) {
      fail(`Mutable :latest image is not admissible: ${image}`);
    }
    if (!/@sha256:[a-f0-9]{64}$/i.test(image)) {
      fail(`Release image must be digest-pinned: ${image}`);
    }
  }

  const sbomFile = argv.sbom ?? latestFileByMtime(path.join(infraRoot, "security", "sbom"), (file) => /sbom.*\.(json|cdx\.json)$/i.test(path.basename(file)));
  if (!sbomFile || !fs.existsSync(sbomFile)) {
    fail("A release SBOM artifact is required. Run generate-sbom or pass --sbom <file>.");
  }
  readJsonFile(sbomFile, sbomFile);

  const policy = readText(path.join(infraRoot, "security", "admission", "cosign-digest-policy.rego"));
  assertMatch(policy, /cosign\.sigstore\.dev\/verified/, "Admission policy must require cosign verification annotation.");
  assertMatch(policy, /slsa\.dev\/provenance/, "Admission policy must require SLSA provenance annotation.");

  if (booleanFlag(argv.requireProvenance)) {
    const provenance = argv.provenance;
    if (!provenance || !fs.existsSync(path.resolve(provenance))) {
      fail("SLSA provenance is required. Pass --provenance <file>.");
    }
  }
  const provenancePath = argv.provenance ? path.resolve(argv.provenance) : null;
  const provenanceValidation = provenancePath
    ? validateSlsaProvenance({
      provenancePath,
      images,
      releaseSha: argv.releaseSha ?? gitEvidence().commit,
      requireReleaseSha: !booleanFlag(argv.skipProvenanceCommitCheck),
    })
    : null;
  if (booleanFlag(argv.verifyCosign)) {
    for (const image of images) {
      run("cosign", ["verify", image]);
    }
  }
  log(`Release artifact admission gate passed with SBOM ${sbomFile}.`);
  return { sbomFile, provenanceValidation };
}

function releaseImageMapFromEnv(env) {
  return Object.fromEntries(releaseImageKeys.map((key) => [key, env[key] ?? null]));
}

function previousReleaseImageMap(env, fileImages = {}) {
  const aliases = {
    BACKEND_IMAGE: ["BACKEND_IMAGE", "backendImage", "PREVIOUS_BACKEND_IMAGE"],
    WEB_IMAGE: ["WEB_IMAGE", "webImage", "PREVIOUS_WEB_IMAGE"],
    WORKER_NOTIFICATIONS_IMAGE: ["WORKER_NOTIFICATIONS_IMAGE", "workerNotificationsImage", "PREVIOUS_WORKER_NOTIFICATIONS_IMAGE"],
    WORKER_JOBS_IMAGE: ["WORKER_JOBS_IMAGE", "workerJobsImage", "PREVIOUS_WORKER_JOBS_IMAGE"],
  };
  const previousArgNames = {
    BACKEND_IMAGE: "previousBackendImage",
    WEB_IMAGE: "previousWebImage",
    WORKER_NOTIFICATIONS_IMAGE: "previousWorkerNotificationsImage",
    WORKER_JOBS_IMAGE: "previousWorkerJobsImage",
  };
  return Object.fromEntries(releaseImageKeys.map((key) => {
    const value = argv[previousArgNames[key]]
      ?? aliases[key].map((alias) => fileImages[alias]).find(Boolean)
      ?? env[`PREVIOUS_${key}`]
      ?? null;
    return [key, value];
  }));
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
  const firstDeploy = Boolean(payload.rollback?.firstDeploy);
  const rollbackFilePath = payload.rollback?.file ?? null;
  const rollbackDryRun = payload.rollback?.dryRun ?? null;
  const jsonPath = writeJsonReport("release", `release-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("release", `release-evidence-${stamp}`, [
    "# Stexor Release Evidence",
    "",
    `Status: ${payload.status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${payload.generatedAt}`,
    `Release: ${payload.releaseName}`,
    `Commit: ${payload.releaseSha ?? "n/a"}`,
    `Environment: ${payload.environment}`,
    `Approved by: ${payload.approvedBy ?? "n/a"}`,
    "",
    "| Image variable | Current image | Rollback image |",
    "| --- | --- | --- |",
    ...releaseImageKeys.map((key) => `| ${key} | \`${currentImages[key] ?? "n/a"}\` | \`${previousImages[key] ?? (firstDeploy ? "first deploy" : "missing")}\` |`),
    "",
    "| Artifact | Path | SHA256 |",
    "| --- | --- | --- |",
    `| SBOM | ${payload.artifacts?.sbom?.path ?? "n/a"} | ${payload.artifacts?.sbom?.sha256 ?? "n/a"} |`,
    `| Provenance | ${payload.artifacts?.provenance?.path ?? "n/a"} | ${payload.artifacts?.provenance?.sha256 ?? "n/a"} |`,
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
  const currentImages = releaseImageMapFromEnv(env);
  const previousImagesFileArg = options.previousImagesFile ?? argv.previousImagesFile;
  const previousImagesFile = previousImagesFileArg ? path.resolve(previousImagesFileArg) : null;
  const previousFileImages = previousImagesFile && fs.existsSync(previousImagesFile) ? readJsonFile(previousImagesFile, previousImagesFile) : {};
  const previousImages = previousReleaseImageMap(env, previousFileImages);
  const sbomPath = options.sbom ?? argv.sbom ?? latestFileByMtime(path.join(infraRoot, "security", "sbom"), (file) => /sbom.*\.(json|cdx\.json)$/i.test(path.basename(file)));
  const provenanceArg = options.provenance ?? argv.provenance;
  const provenancePath = provenanceArg ? path.resolve(provenanceArg) : null;
  const signatureBundleArg = options.signatureBundle ?? argv.signatureBundle;
  const signatureBundlePath = signatureBundleArg ? path.resolve(signatureBundleArg) : null;
  const releaseSha = options.releaseSha ?? argv.releaseSha ?? gitEvidence().commit;
  const releaseName = options.releaseName ?? argv.releaseName ?? releaseSha?.slice(0, 12) ?? `release-${reportTimestamp()}`;
  const rollbackProjectName = options.rollbackProjectName ?? argv.rollbackProjectName ?? argv.projectName ?? "enterprise_prod";
  const rollbackServices = csvList(options.rollbackServices ?? argv.rollbackServices ?? argv.services, "backend,web,worker-notifications,worker-jobs");
  const rollbackComposeFiles = csvList(options.rollbackComposeFiles ?? argv.rollbackComposeFiles ?? argv.composeFiles, "compose.yaml,compose.prod.yaml");
  const generatedAt = new Date().toISOString();
  const issues = [];
  let provenanceValidation = null;

  if (!planOnly) {
    try {
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
      if (requireProvenance && !provenancePath) {
        fail("SLSA provenance is required. Pass --provenance <file>.");
      }
      if (provenancePath && !fs.existsSync(provenancePath)) {
        fail(`SLSA provenance artifact not found: ${provenancePath}`);
      }
      if (signatureBundlePath && !fs.existsSync(signatureBundlePath)) {
        fail(`Signature bundle artifact not found: ${signatureBundlePath}`);
      }
      const artifactGate = await releaseArtifactGate();
      provenanceValidation = artifactGate.provenanceValidation;
    } catch (error) {
      issues.push(String(error?.message ?? error));
    }
  }

  const sbom = planOnly && !sbomPath ? null : safeReleaseArtifactRef(sbomPath, issues, "SBOM");
  const provenance = safeReleaseArtifactRef(provenancePath, issues, "SLSA provenance");
  const signatureBundle = safeReleaseArtifactRef(signatureBundlePath, issues, "Signature bundle");
  const rollbackComplete = releaseImageKeys.every((key) => Boolean(previousImages[key]));
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

  const payload = {
    generatedAt,
    status: planOnly ? "plan" : issues.length ? "failed" : "passed",
    mode: planOnly ? "plan" : "evidence",
    releaseName,
    releaseSha,
    approvedBy: argv.approvedBy ?? null,
    environment: argv.environment ?? "production",
    git: gitEvidence(),
    envFile: fs.existsSync(envFile) ? envFile : null,
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
      provenance,
      signatureBundle,
    },
    attestations: {
      provenanceRequired: options.requireProvenance ?? booleanFlag(argv.requireProvenance),
      slsaProvenance: provenanceValidation,
      cosignVerified: (options.verifyCosign ?? booleanFlag(argv.verifyCosign)) && !planOnly,
    },
    issues,
    nextCommands: [
      "sh ./scripts/release-artifact-gate.sh --requireProvenance",
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

async function rollbackRelease() {
  log("==> Release rollback");
  const envFile = path.resolve(argv.envFile ?? path.join(infraRoot, ".env"));
  if (!fs.existsSync(envFile)) {
    fail(`Env file not found: ${envFile}`);
  }
  const rollbackFile = argv.rollbackFile ? path.resolve(argv.rollbackFile) : null;
  const fileImages = rollbackFile ? readJsonFile(rollbackFile, rollbackFile) : {};
  const imageOverrides = {
    BACKEND_IMAGE: argv.backendImage ?? fileImages.BACKEND_IMAGE ?? fileImages.backendImage,
    WEB_IMAGE: argv.webImage ?? fileImages.WEB_IMAGE ?? fileImages.webImage,
    WORKER_NOTIFICATIONS_IMAGE: argv.workerNotificationsImage ?? fileImages.WORKER_NOTIFICATIONS_IMAGE ?? fileImages.workerNotificationsImage,
    WORKER_JOBS_IMAGE: argv.workerJobsImage ?? fileImages.WORKER_JOBS_IMAGE ?? fileImages.workerJobsImage,
  };
  for (const [key, image] of Object.entries(imageOverrides)) {
    assertImmutableImageRef(key, image);
  }
  const projectName = argv.projectName ?? "enterprise_prod";
  const services = csvList(argv.services, "backend,web,worker-notifications,worker-jobs");
  const composeFiles = csvList(argv.composeFiles, "compose.yaml,compose.prod.yaml");
  const envText = fs.readFileSync(envFile, "utf8");
  const stamp = reportTimestamp();
  const rollbackPlan = writeRollbackPlanReport({
    envFile,
    envText,
    rollbackFile,
    imageOverrides,
    projectName,
    composeFiles,
    services,
    mode: booleanFlag(argv.confirmRollback) ? "apply" : "dry-run",
    stamp,
  });
  if (!booleanFlag(argv.confirmRollback)) {
    log(`Rollback dry-run passed. Plan written to ${rollbackPlan.jsonPath} and ${rollbackPlan.markdownPath}`);
    log("Re-run with --confirmRollback to update the env file, restart selected services and run infra-health.");
    return;
  }
  const backupEnvPath = `${envFile}.rollback-backup-${stamp}`;
  fs.copyFileSync(envFile, backupEnvPath);
  fs.writeFileSync(envFile, rollbackPlan.nextEnvText, "utf8");
  run("docker", ["compose", "--env-file", envFile, "-p", projectName, ...composeFiles.flatMap((file) => ["-f", path.resolve(infraRoot, file)]), "up", "-d", ...services]);
  await infraHealth();
  log(`Rollback applied. Previous env copied to ${backupEnvPath}. Plan: ${rollbackPlan.jsonPath}`);
}

async function drReadinessCheck() {
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
  ]);
  log("DR / PITR readiness check passed.");
}

async function securityMatrix() {
  log("==> Security test matrix");
  await testingHygiene();
  const securitySpec = readText(path.join(sourceRoot, "e2e", "security-guards.spec.ts"));
  const accountSpec = readText(path.join(sourceRoot, "e2e", "account-auth.spec.ts"));
  const opsScript = readText(path.join(infraRoot, "scripts", "stexor-ops.mjs"));
  assertMatch(securitySpec, /cross-site mutating requests are blocked/, "Security E2E must cover cross-site request blocking.");
  assertMatch(securitySpec, /require the CSRF header/, "Security E2E must cover CSRF header enforcement.");
  assertMatch(accountSpec, /loginWithBackupCodeRecovery/, "Account E2E must cover backup-code recovery login.");
  assertMatch(accountSpec, /expectBackupCodeStatus\(page, backupCode \?\? "", 400\)/, "Account E2E/integration must cover backup-code single-use blocking.");
  assertMatch(opsScript, /passkey login options for added account/, "Account integration must cover passkey requested-account isolation.");
  await securitySmoke();
  await accountIntegrationTests();
  log("Security test matrix passed.");
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
  const stopped = [];
  try {
    for (const container of targets) {
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
      await new Promise((resolve) => setTimeout(resolve, 5000));
      await runtimeHealthChecks();
    }
    await faultInjectionTests();
    await loadProfile();
    log("Staging chaos profile passed.");
  } finally {
    for (const container of stopped.reverse()) {
      run("docker", ["start", container], { allowFailure: true, capture: true });
    }
  }
}

async function governanceCheck() {
  log("==> Governance / release control check");
  const workflow = readText(path.join(sourceRoot, ".github", "workflows", "enterprise-ci.yml"));
  const branchProtection = JSON.parse(readText(path.join(infraRoot, "governance", "github-branch-protection.json")));
  const environmentsPolicy = JSON.parse(readText(path.join(infraRoot, "governance", "github-environments.json")));
  const actionsRuntimePolicy = JSON.parse(readText(path.join(infraRoot, "governance", "github-actions-runtime.json")));
  const infraWorkflow = readText(path.join(infraRoot, ".github", "workflows", "enterprise-infra.yml"));
  const runbook = readText(path.join(infraRoot, "RUNBOOK.md"));
  for (const job of ["quality", "compose", "supply-chain", "enterprise-readiness"]) {
    assertMatch(workflow, new RegExp(`^\\s{2}${job}:`, "m"), `Enterprise CI must define ${job} job.`);
    if (!branchProtection.required_status_checks.contexts.includes(job)) {
      fail(`Branch protection must require ${job}.`);
    }
  }
  const environmentNames = new Set(environmentsPolicy.environments?.map((environment) => environment.name) ?? []);
  for (const name of ["staging", "production"]) {
    if (!environmentNames.has(name)) {
      fail(`GitHub environments policy must define ${name}.`);
    }
  }
  if (actionsRuntimePolicy.repository?.required_secrets?.some((item) => item.name === "STEXOR_APP_REPO_TOKEN")) {
    fail("GitHub Actions runtime policy must not require project repository checkout tokens.");
  }
  assertNoMatch(infraWorkflow, /Stexor-account|STEXOR_APP_REPO_TOKEN|Checkout application source/, "Infrastructure CI must not checkout or require Stexor application repositories.");
  assertMatch(infraWorkflow, /dast-zap:[\s\S]*environment:\s*\r?\n\s+name:\s+staging/, "DAST job must target the staging GitHub environment.");
  assertMatch(infraWorkflow, /deploy-hostinger:[\s\S]*environment:\s*\r?\n\s+name:\s+production/, "Hostinger deploy job must target the production GitHub environment.");
  assertMatch(infraWorkflow, /deploy-hostinger:[\s\S]*concurrency:[\s\S]*stexor-production-deploy[\s\S]*cancel-in-progress:\s+false/, "Production deploys must be serialized.");
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
  const repo = argv.repo ?? process.env.STEXOR_GITHUB_REPOSITORY ?? process.env.GITHUB_REPOSITORY;
  if (!repo || !/^[^/\s]+\/[^/\s]+$/.test(repo)) {
    fail("Provide --repo owner/name or set STEXOR_GITHUB_REPOSITORY/GITHUB_REPOSITORY.");
  }
  return repo;
}

async function githubApi(method, apiPath, body = undefined) {
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (!token) {
    fail("Set GITHUB_TOKEN or GH_TOKEN before applying or verifying live GitHub governance.");
  }
  const response = await requestRaw(method, `https://api.github.com${apiPath}`, {
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${token}`,
      "User-Agent": "stexor-platform-infrastructure",
      "X-GitHub-Api-Version": process.env.GITHUB_API_VERSION ?? "2026-03-10",
    },
    body,
    timeoutMs: Number(argv.timeoutMs ?? 15000),
  });
  if (response.status < 200 || response.status >= 300) {
    fail(`GitHub API ${method} ${apiPath} failed with HTTP ${response.status}: ${response.text}`);
  }
  return response.text ? JSON.parse(response.text) : null;
}

function assertRemoteBranchProtectionMatches(policy, remote) {
  const remoteContexts = remote?.required_status_checks?.contexts ?? remote?.required_status_checks?.checks?.map((check) => check.context) ?? [];
  const missingContexts = policy.required_status_checks.contexts.filter((context) => !remoteContexts.includes(context));
  if (missingContexts.length) {
    fail(`Remote GitHub branch protection is missing required status checks: ${missingContexts.join(", ")}`);
  }
  const review = remote?.required_pull_request_reviews ?? {};
  if (Number(review.required_approving_review_count ?? 0) < policy.required_pull_request_reviews.required_approving_review_count) {
    fail("Remote GitHub branch protection requires too few approving reviews.");
  }
  if (Boolean(review.dismiss_stale_reviews) !== Boolean(policy.required_pull_request_reviews.dismiss_stale_reviews)) {
    fail("Remote GitHub branch protection dismiss_stale_reviews does not match policy.");
  }
  if (Boolean(review.require_code_owner_reviews) !== Boolean(policy.required_pull_request_reviews.require_code_owner_reviews)) {
    fail("Remote GitHub branch protection require_code_owner_reviews does not match policy.");
  }
  const requiredBooleans = [
    ["required_linear_history", policy.required_linear_history],
    ["allow_force_pushes", policy.allow_force_pushes],
    ["allow_deletions", policy.allow_deletions],
    ["required_conversation_resolution", policy.required_conversation_resolution],
  ];
  for (const [key, expected] of requiredBooleans) {
    if (expected === undefined) continue;
    const actual = typeof remote?.[key] === "object" && remote[key] !== null && "enabled" in remote[key]
      ? remote[key].enabled
      : remote?.[key];
    if (Boolean(actual) !== Boolean(expected)) {
      fail(`Remote GitHub branch protection ${key}=${actual} does not match expected ${expected}.`);
    }
  }
}

async function githubBranchProtection() {
  log("==> GitHub branch protection");
  const repo = requiredGithubRepo();
  const branch = String(argv.branch ?? "main");
  const policy = githubBranchProtectionPolicy();
  const apiPath = `/repos/${repo}/branches/${encodeURIComponent(branch)}/protection`;

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
  const refs = Array.isArray(environment.reviewers) ? [...environment.reviewers] : [];
  if (!environment.required_reviewers_env) {
    return refs;
  }
  const raw = process.env[environment.required_reviewers_env];
  if (!raw || !raw.trim()) {
    return refs;
  }
  const trimmed = raw.trim();
  if (trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) {
      fail(`${environment.required_reviewers_env} must be a JSON array or a comma-separated reviewer list.`);
    }
    refs.push(...parsed);
    return refs;
  }
  refs.push(...trimmed.split(",").map((item) => item.trim()).filter(Boolean));
  return refs;
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
      fail(`Set ${environment.required_reviewers_env} before applying the ${environment.name} GitHub environment.`);
    }
  }
}

function dryRunGithubEnvironmentPayload(environment) {
  return {
    wait_timer: Number(environment.wait_timer ?? 0),
    prevent_self_review: Boolean(environment.prevent_self_review),
    reviewers: environment.required_reviewers_env ? `$${environment.required_reviewers_env}` : null,
    require_reviewers_on_apply: Boolean(environment.require_reviewers_on_apply),
    deployment_branch_policy: environment.deployment_branch_policy ?? null,
  };
}

function assertRemoteGithubEnvironmentMatches(expected, remote) {
  const rules = Array.isArray(remote?.protection_rules) ? remote.protection_rules : [];
  const expectedWait = Number(expected.wait_timer ?? 0);
  const waitRule = rules.find((rule) => rule.type === "wait_timer");
  const actualWait = Number(waitRule?.wait_timer ?? 0);
  if (actualWait !== expectedWait) {
    fail(`Remote GitHub environment ${expected.name} wait_timer=${actualWait} does not match expected ${expectedWait}.`);
  }

  const reviewerRule = rules.find((rule) => rule.type === "required_reviewers");
  if (expected.require_reviewers_on_apply) {
    const reviewerCount = Array.isArray(reviewerRule?.reviewers) ? reviewerRule.reviewers.length : 0;
    if (reviewerCount <= 0) {
      fail(`Remote GitHub environment ${expected.name} does not require deployment reviewers.`);
    }
  }
  if (reviewerRule && Boolean(reviewerRule.prevent_self_review) !== Boolean(expected.prevent_self_review)) {
    fail(`Remote GitHub environment ${expected.name} prevent_self_review does not match policy.`);
  }

  const expectedBranchPolicy = expected.deployment_branch_policy;
  const remoteBranchPolicy = remote?.deployment_branch_policy;
  if (expectedBranchPolicy) {
    for (const key of ["protected_branches", "custom_branch_policies"]) {
      if (Boolean(remoteBranchPolicy?.[key]) !== Boolean(expectedBranchPolicy[key])) {
        fail(`Remote GitHub environment ${expected.name} deployment_branch_policy.${key} does not match policy.`);
      }
    }
  } else if (remoteBranchPolicy !== null && remoteBranchPolicy !== undefined) {
    fail(`Remote GitHub environment ${expected.name} should not have a deployment branch policy.`);
  }
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
    log("Set reviewer env vars such as GITHUB_PRODUCTION_REVIEWERS=user:login,team:platform-admins.");
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
  if (!expectedSha || !/^[a-f0-9]{40}$/i.test(expectedSha)) {
    issues.push(`expected SHA is missing or invalid: ${expectedSha ?? "n/a"}`);
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
  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : "passed",
    mode,
    repo,
    workflow,
    branch,
    expectedSha,
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

function gitEvidence() {
  const rev = run("git", ["rev-parse", "HEAD"], { capture: true, allowFailure: true });
  const branch = run("git", ["rev-parse", "--abbrev-ref", "HEAD"], { capture: true, allowFailure: true });
  const status = run("git", ["status", "--short"], { capture: true, allowFailure: true });
  return {
    commit: rev.status === 0 ? String(rev.stdout ?? "").trim() : null,
    branch: branch.status === 0 ? String(branch.stdout ?? "").trim() : null,
    dirty: status.status === 0 ? String(status.stdout ?? "").trim().split(/\r?\n/).filter(Boolean).length > 0 : null,
  };
}

function releaseCommitShaCandidate() {
  const release = latestJsonReport("release", "release-evidence-", (payload) => payload.mode === "evidence");
  const releaseSha = release?.payload?.releaseSha ?? release?.payload?.git?.commit ?? release?.payload?.git?.sha;
  if (releaseSha && /^[a-f0-9]{40}$/i.test(String(releaseSha))) {
    return String(releaseSha);
  }
  return null;
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

function buildPreGoLiveReadinessMatrix({ steps, options, repo }) {
  const localPolicySteps = [
    "static-security-check",
    "governance-check",
    "ha-config-check",
    "managed-secrets-preflight",
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
      status: evidenceStepStatus(steps, "production-preflight"),
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
      status: evidenceStepStatus(steps, "offsite-restore-drill-restic-dry-run"),
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
      status: evidenceGroupStatus(steps, githubRemoteSteps, options.verifyGithubRemote),
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

async function preGoLiveEvidence() {
  log("==> Pre go-live evidence pack");
  const repo = argv.repo ?? process.env.STEXOR_GITHUB_REPOSITORY ?? process.env.GITHUB_REPOSITORY ?? null;
  const branch = String(argv.branch ?? "main");
  const infraOnly = booleanFlag(argv.infraOnly);
  const steps = [];
  const providerEvidence = [
    "Hostinger Ubuntu LTS bootstrap and hardening executed on the real VPS.",
    "Cloudflare DNS/CDN/WAF/Access configured on the real zone and origin lock applied.",
    "External uptime monitors created and confirmed from outside the VPS network.",
    "Off-site Restic repository configured and remote restore tested.",
    "Real staging deploy, DAST run and production deploy completed.",
    "Public-path load benchmark archived.",
  ];

  await collectEvidenceStep(steps, {
    name: "static-security-check",
    category: "local-policy",
    fn: infraOnly ? staticSecurityInfraOnlyCheck : staticSecurityCheck,
  });
  await collectEvidenceStep(steps, { name: "governance-check", category: "local-policy", fn: governanceCheck });
  await collectEvidenceStep(steps, { name: "ha-config-check", category: "local-policy", fn: haConfigCheck });
  await collectEvidenceStep(steps, { name: "managed-secrets-preflight", category: "local-policy", fn: managedSecretsPreflight });
  await collectEvidenceStep(steps, { name: "secret-rotation-evidence-plan", category: "local-policy", fn: secretRotationEvidence });
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
    await collectEvidenceStep(steps, { name: "full-restore-drill", category: "disaster-recovery", fn: fullRestoreDrill });
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
    includeOffsiteRestoreDryRun: booleanFlag(argv.includeOffsiteRestoreDryRun),
    verifyGithubRemote: booleanFlag(argv.verifyGithubRemote),
  };
  const readinessMatrix = buildPreGoLiveReadinessMatrix({ steps, options, repo });
  const failedRequired = steps.filter((step) => step.required && step.status === "failed");
  const readinessMissing = readinessMatrix.filter((item) => item.required && item.status !== "passed");
  const missingOptions = [
    !options.includeProductionPreflight ? "includeProductionPreflight" : null,
    !options.includeRuntime ? "includeRuntime" : null,
    !options.includeRestoreDrill ? "includeRestoreDrill" : null,
    !options.includeOffsiteRestoreDryRun ? "includeOffsiteRestoreDryRun" : null,
    !options.verifyGithubRemote ? "verifyGithubRemote" : null,
  ].filter(Boolean);
  const issues = [
    ...failedRequired.map((step) => `${step.name}: ${step.error ?? "failed"}`),
    ...readinessMissing.map((item) => `${item.id}: ${item.nextAction}`),
    ...missingOptions.map((option) => `missing option: --${option}`),
  ];
  const payload = {
    generatedAt,
    status: issues.length ? "failed" : "passed",
    repo,
    branch,
    git: gitEvidence(),
    options,
    steps,
    readinessMatrix,
    missingOptions,
    issues,
    providerEvidenceRequired: providerEvidence,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("go-live", `pre-go-live-evidence-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("go-live", `pre-go-live-evidence-${stamp}`, [
    "# Stexor Pre Go-Live Evidence",
    "",
    `Status: ${payload.status}`,
    `Generated at: ${generatedAt}`,
    `Repository: ${repo ?? "not provided"}`,
    `Git commit: ${payload.git.commit ?? "unknown"}`,
    `Git branch: ${payload.git.branch ?? "unknown"}`,
    `Dirty worktree: ${payload.git.dirty === null ? "unknown" : payload.git.dirty ? "yes" : "no"}`,
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
    "## Provider Evidence Still Required",
    "",
    ...providerEvidence.map((item) => `- ${item}`),
  ]);
  log(`Pre go-live evidence written to ${jsonPath} and ${markdownPath}`);
  if (issues.length && !booleanFlag(argv.allowFailures)) {
    fail(`Pre go-live evidence status=${payload.status} with ${issues.length} issue(s). Reports: ${jsonPath}, ${markdownPath}`);
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
      try {
        payload = JSON.parse(readText(filePath));
      } catch {
        payload = null;
      }
      const generatedAt = payload?.generatedAt ? Date.parse(payload.generatedAt) : NaN;
      const timestamp = Number.isFinite(generatedAt) ? generatedAt : fs.statSync(filePath).mtimeMs;
      return { filePath, payload, timestamp };
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

function addGoNoGoCheck(checks, { name, passed, detail, report = null, required = true }) {
  checks.push({
    name,
    required,
    status: passed ? "passed" : "failed",
    detail,
    reportPath: report?.filePath ?? null,
    generatedAt: report?.payload?.generatedAt ?? null,
  });
}

function goNoGoRemediation(check) {
  const remediations = {
    "vps-bootstrap-applied": {
      actions: [
        "Run the VPS bootstrap on the actual Hostinger Ubuntu LTS host in apply mode, not from Docker Desktop or a diagnostic container.",
        "Archive the passing bootstrap JSON/Markdown apply reports outside Git before running the final go/no-go gate.",
      ],
      commands: [
        "sudo sh ./scripts/vps-bootstrap-ubuntu.sh --apply --deploy-user <deploy-user>",
      ],
      evidence: "reports/vps-bootstrap/vps-bootstrap-apply-*.json with mode=apply and status=applied",
    },
    "vps-hardening-applied": {
      actions: [
        "Run the VPS hardening on the actual Hostinger Ubuntu LTS host in apply mode.",
        "Reload SSH only after key-based access and the target SSH port are verified, so the effective daemon matches the hardened config.",
        "If an existing Docker daemon config is missing Stexor hardening keys, review the generated template and rerun with the explicit replacement flag so a backup is created.",
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
        "Run the host hardening and readiness checks on the actual Hostinger Ubuntu LTS VPS, not from Docker Desktop or a diagnostic container.",
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
        "Initialize or upgrade the Stexor Secret Manager store so every Compose secret is managed, materialized and audited.",
        "Rotate stale keyrings and opaque secrets inside a planned maintenance window, then rotate the Stexor Local KMS active key.",
        "Archive the passing non-secret rotation report outside Git before the final go/no-go gate.",
      ],
      commands: [
        "sh ./scripts/stexor-secret-manager.sh init",
        "sh ./scripts/stexor-secret-manager.sh verify",
        "sh ./scripts/stexor-secret-manager.sh rotate --name session_signing_keys",
        "sh ./scripts/stexor-secret-manager.sh kms-rotate",
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
        "With Cloudflare enabled, require Cloudflare edge evidence in the target preflight.",
      ],
      commands: [
        "sh ./scripts/load-benchmark.sh --url https://api.<domain>/health --profiles 50,100,500 --requirePublicTarget --requireEdgeEvidence --expectedEdgeProvider cloudflare",
      ],
      evidence: "reports/load/load-benchmark-*.json with status=passed, public target evidence and required profiles",
    },
    "release-evidence-and-rollback": {
      actions: [
        "Generate release evidence from digest-pinned images, SBOM, SLSA provenance and previous release image digests.",
        "Keep the rollback dry-run report linked from the release evidence pack.",
      ],
      commands: [
        "sh ./scripts/release-evidence.sh --envFile .env --sbom security/sbom/<sbom>.json --provenance release/<provenance>.json --previousImagesFile release/previous-images.json --requireProvenance",
      ],
      evidence: "reports/release/release-evidence-*.json with mode=evidence, status=passed, SLSA provenance passed and rollback validated",
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

const evidenceBundleReportSpecs = [
  { directory: "go-no-go", prefix: "production-go-no-go-", label: "production-go-no-go", required: true },
  { directory: "production-readiness", prefix: "production-readiness-", label: "production-readiness-live", required: true },
  { directory: "github-actions", prefix: "github-actions-run-", label: "github-actions-run", required: true },
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
  { directory: "hostinger-go-live", prefix: "hostinger-go-live-", label: "hostinger-go-live", required: false },
  { directory: "backups", prefix: "", label: "backup-execution-reports", required: false },
  { directory: "restore-drills", prefix: "full-restore-drill-", label: "full-restore-drill", required: false },
  { directory: "failure-tests", prefix: "failure-tests-", label: "failure-tests", required: false },
];

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

function listEvidenceBundleReportFiles({ allReports }) {
  const files = [];
  const missing = [];
  for (const spec of evidenceBundleReportSpecs) {
    const directory = path.join(infraRoot, "reports", spec.directory);
    if (!fs.existsSync(directory)) {
      if (spec.required) missing.push({ label: spec.label, reason: "missing report directory" });
      continue;
    }
    if (allReports) {
      const matches = fs.readdirSync(directory)
        .filter((name) => name.startsWith(spec.prefix) && /\.(json|md)$/i.test(name))
        .map((name) => path.join(directory, name))
        .filter((filePath) => fs.statSync(filePath).isFile())
        .sort();
      if (!matches.length && spec.required) missing.push({ label: spec.label, reason: "missing reports" });
      files.push(...matches);
      continue;
    }
    const report = latestJsonReport(spec.directory, spec.prefix);
    if (!report) {
      if (spec.required) missing.push({ label: spec.label, reason: "missing latest JSON report" });
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

function latestEvidenceBundleDir(outputRoot) {
  if (!fs.existsSync(outputRoot)) {
    return null;
  }
  const candidates = fs.readdirSync(outputRoot)
    .filter((name) => name.startsWith("stexor-evidence-bundle-"))
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
    return normalizedPath;
  }
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    issues.push(`${normalizedPath}: file missing from bundle`);
    return normalizedPath;
  }
  const stat = fs.statSync(filePath);
  if (Number.isInteger(entry.sizeBytes) && stat.size !== entry.sizeBytes) {
    issues.push(`${normalizedPath}: size mismatch manifest=${entry.sizeBytes} actual=${stat.size}`);
  }
  const actualHash = sha256File(filePath);
  if (String(entry.sha256 ?? "").toLowerCase() !== actualHash) {
    issues.push(`${normalizedPath}: sha256 mismatch`);
  }
  return normalizedPath;
}

function evidenceBundleReportPasses(spec, payload) {
  if (!payload || typeof payload !== "object") {
    return { passed: false, detail: "report payload is missing" };
  }
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
  log("==> Evidence bundle");
  const allReports = booleanFlag(argv.allReports);
  const noArchive = booleanFlag(argv.noArchive);
  const stamp = reportTimestamp();
  const outputRoot = path.resolve(argv.outputDir ?? path.join(infraRoot, ".tmp", "evidence-bundles"));
  fs.mkdirSync(outputRoot, { recursive: true });
  const bundleName = `stexor-evidence-bundle-${stamp}`;
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

  const { files: reportFiles, missing } = listEvidenceBundleReportFiles({ allReports });
  for (const reportFile of reportFiles) {
    const relativePath = path.relative(infraRoot, reportFile).replaceAll("\\", "/");
    copyEvidenceFile(reportFile, relativePath, "report");
  }
  for (const docPath of evidenceBundleDocPaths) {
    copyEvidenceFile(path.join(infraRoot, docPath), docPath, "document");
  }

  const manifestPath = path.join(bundleDir, "manifest.json");
  const manifest = {
    version: 1,
    generatedAt: new Date().toISOString(),
    mode: allReports ? "all-reports" : "latest-per-category",
    source: {
      git: gitEvidence(),
      command: "evidence-bundle",
    },
    policy: {
      includesSecrets: false,
      includesBackupArtifacts: false,
      includesReleaseArtifacts: false,
      outputDirectoryIgnoredByGit: outputRoot.includes(`${path.sep}.tmp${path.sep}`) || path.basename(path.dirname(outputRoot)) === ".tmp",
    },
    missingRequiredEvidence: missing,
    entries: Array.from(copied.values()).sort((a, b) => a.path.localeCompare(b.path)),
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  const manifestMarkdownPath = path.join(bundleDir, "manifest.md");
  fs.writeFileSync(manifestMarkdownPath, [
    "# Stexor Evidence Bundle",
    "",
    `Generated at: ${manifest.generatedAt}`,
    `Mode: ${manifest.mode}`,
    `Git commit: ${manifest.source.git.commit ?? "unknown"}`,
    `Git dirty: ${manifest.source.git.dirty ? "yes" : "no"}`,
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
}

async function evidenceBundleVerify() {
  log("==> Evidence bundle verify");
  const outputRoot = path.resolve(argv.outputDir ?? path.join(infraRoot, ".tmp", "evidence-bundles"));
  const bundleDir = path.resolve(argv.bundleDir ?? argv._[0] ?? latestEvidenceBundleDir(outputRoot) ?? "");
  const requireComplete = booleanFlag(argv.requireComplete);
  const issues = [];
  if (!bundleDir || !fs.existsSync(bundleDir) || !fs.statSync(bundleDir).isDirectory()) {
    fail(`Evidence bundle directory not found. Pass --bundleDir <path> or create one with evidence-bundle. Looked in: ${outputRoot}`);
  }
  const manifestPath = path.join(bundleDir, "manifest.json");
  const manifestMarkdownPath = path.join(bundleDir, "manifest.md");
  const summaryPath = path.join(bundleDir, "summary.json");
  if (!fs.existsSync(manifestPath)) {
    fail(`Missing evidence bundle manifest: ${manifestPath}`);
  }
  const manifest = readJsonFile(manifestPath, manifestPath);
  if (manifest.version !== 1) {
    issues.push(`manifest.version must be 1, found ${manifest.version ?? "missing"}`);
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
  const missingRequiredEvidence = Array.isArray(manifest.missingRequiredEvidence) ? manifest.missingRequiredEvidence : [];
  if (!Array.isArray(manifest.missingRequiredEvidence)) {
    issues.push("manifest.missingRequiredEvidence must be an array");
  }
  if (requireComplete && missingRequiredEvidence.length) {
    issues.push(`required evidence is still missing: ${missingRequiredEvidence.map((item) => item.label ?? "unknown").join(", ")}`);
  }
  if (!Array.isArray(manifest.entries) || !manifest.entries.length) {
    issues.push("manifest.entries must be a non-empty array");
  }
  const paths = new Set();
  for (const entry of Array.isArray(manifest.entries) ? manifest.entries : []) {
    const normalizedPath = validateEvidenceBundleEntry(entry, bundleDir, issues);
    if (!normalizedPath) {
      continue;
    }
    if (paths.has(normalizedPath)) {
      issues.push(`${normalizedPath}: duplicate manifest entry`);
    }
    paths.add(normalizedPath);
  }
  for (const docPath of evidenceBundleDocPaths) {
    if (!paths.has(docPath)) {
      issues.push(`missing required document entry: ${docPath}`);
    }
  }
  const missingLabels = new Set(missingRequiredEvidence.map((item) => item.label));
  for (const spec of evidenceBundleReportSpecs) {
    if (spec.required && !missingLabels.has(spec.label)) {
      const reportEntries = [...paths]
        .filter((entryPath) => entryPath.startsWith(`reports/${spec.directory}/`) && path.basename(entryPath).startsWith(spec.prefix) && entryPath.endsWith(".json"))
        .sort();
      if (!reportEntries.length) {
        issues.push(`missing required report entry: ${spec.label}`);
      } else if (requireComplete) {
        const reportPath = path.join(bundleDir, reportEntries.at(-1));
        const payload = readJsonFile(reportPath, reportPath);
        const result = evidenceBundleReportPasses(spec, payload);
        if (!result.passed) {
          issues.push(`required report is not passing: ${spec.label}; ${result.detail}`);
        }
      }
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
  } else {
    issues.push("missing summary.json");
  }

  const stamp = reportTimestamp();
  const payload = {
    generatedAt: new Date().toISOString(),
    status: issues.length ? "failed" : "passed",
    bundleDir,
    requireComplete,
    entryCount: paths.size,
    missingRequiredEvidence,
    issues,
  };
  const jsonPath = writeJsonReport("evidence-bundle-verify", `evidence-bundle-verify-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("evidence-bundle-verify", `evidence-bundle-verify-${stamp}`, [
    "# Evidence Bundle Verify",
    "",
    `Status: ${payload.status}`,
    `Bundle: ${bundleDir}`,
    `Require complete: ${requireComplete}`,
    `Entries: ${payload.entryCount}`,
    "",
    "## Missing Required Evidence",
    "",
    ...(missingRequiredEvidence.length ? missingRequiredEvidence.map((item) => `- ${item.label}: ${item.reason}`) : ["- none"]),
    "",
    "## Issues",
    "",
    ...(issues.length ? issues.map((issue) => `- ${issue}`) : ["- none"]),
  ]);
  log(`Evidence bundle verification report written to ${jsonPath} and ${markdownPath}`);
  if (issues.length) {
    fail(`Evidence bundle verification failed with ${issues.length} issue(s). Report: ${jsonPath}`);
  }
  log("Evidence bundle verification passed.");
}

async function productionGoNoGo() {
  log("==> Production go/no-go evidence gate");
  const { policyPath, policy } = productionGoNoGoPolicy();
  const enforce = booleanFlag(argv.enforce);
  const checks = [];
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
    secretRotation: 24,
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

  const preGoLive = latestJsonReport("go-live", "pre-go-live-evidence-");
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
  addGoNoGoCheck(checks, {
    name: "pre-go-live-evidence-complete",
    passed: Boolean(preGoLive && preFresh.fresh && preGoLive.payload.status === "passed" && preRequiredFailures.length === 0 && preMissingOptions.length === 0 && preMatrixRequiredFailures.length === 0),
    detail: preGoLive
      ? `${preFresh.detail}; status=${preGoLive.payload.status ?? "unknown"}; requiredFailures=${preRequiredFailures.length}; missingOptions=${preMissingOptions.join(",") || "none"}; readinessMissing=${preMatrixRequiredFailures.map((item) => item.id).join(",") || "none"}`
      : preFresh.detail,
    report: preGoLive,
  });

  const expectedWorkflow = policy.requiredGithubWorkflow ?? "enterprise-infra.yml";
  const releaseSha = releaseCommitShaCandidate() ?? gitEvidence().commit;
  const githubActionsRun = latestJsonReport("github-actions", "github-actions-run-", (payload) => (
    !policy.requireGithubActionsRunSuccess
    || (
      payload.mode === "verifyRemote"
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
    && (!releaseSha || String(githubActionsRun.payload.expectedSha ?? "").toLowerCase() === String(releaseSha).toLowerCase())
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
  addGoNoGoCheck(checks, {
    name: "disaster-recovery-rpo-rto-offsite",
    passed: Boolean(dr && drFresh.fresh && dr.payload.status === "passed" && backupFailures.length === 0 && offsiteRestoreOk),
    detail: dr
      ? `${drFresh.detail}; status=${dr.payload.status}; backupFailures=${backupFailures.map((item) => item.family).join(",") || "none"}; offsiteRestore=${offsiteRestoreOk ? "yes" : "no"}; offsiteRepository=${dr.payload.offsiteEvidence?.latestRestoreOffsite === true ? "yes" : "no"}; offsiteCoverage=${dr.payload.offsiteEvidence?.latestRestoreCoverage?.complete === true ? "yes" : "no"}`
      : drFresh.detail,
    report: dr,
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
    && (payload.results ?? []).every((result) => publicEvidenceUrl(result.url))
  ));
  const uptimeFresh = reportFreshDetail(uptime, maxAge.uptime);
  const latestUptimeFresh = reportFreshDetail(latestUptimeReport, maxAge.uptime);
  const uptimeResults = uptime?.payload?.results ?? [];
  const uptimeFailed = uptimeResults.filter((result) => !result.ok);
  const uptimePublic = uptimeResults.every((result) => publicEvidenceUrl(result.url));
  const uptimeProviderVerified = uptime?.payload?.providerEvidence?.verified === true;
  addGoNoGoCheck(checks, {
    name: "external-uptime-provider",
    passed: Boolean(uptime && uptimeFresh.fresh && uptimeResults.length > 0 && uptimeFailed.length === 0 && uptimePublic && uptimeProviderVerified),
    detail: uptime
      ? `${uptimeFresh.detail}; failedTargets=${uptimeFailed.map((item) => item.name).join(",") || "none"}; publicTargets=${uptimePublic ? "yes" : "no"}; provider=${uptimeProviderVerified ? uptime.payload.providerEvidence.provider : "missing"}`
      : latestUptimeReport
        ? `missing provider-verified public uptime report; latestProvider=${latestUptimeReport.payload.providerEvidence?.verified ? latestUptimeReport.payload.providerEvidence.provider : "missing"}; ${latestUptimeFresh.detail}`
        : uptimeFresh.detail,
    report: uptime ?? latestUptimeReport,
  });

  const latestLoadReport = latestJsonReport("load", "load-benchmark-");
  const load = latestJsonReport("load", "load-benchmark-", (payload) => {
    const target = payload.target ?? {};
    const publicTarget = !policy.requirePublicLoadTarget || (target.public === true && publicEvidenceUrl(payload.url));
    const edgeEvidence = !policy.requireLoadEdgeEvidence || (
      target.edgeRequired === true
      && target.edge?.providerMatched === true
      && Boolean(target.edge?.provider)
    );
    return publicTarget && edgeEvidence;
  });
  const loadFresh = reportFreshDetail(load, maxAge.load);
  const latestLoadFresh = reportFreshDetail(latestLoadReport, maxAge.load);
  const requiredProfiles = Array.isArray(policy.requiredLoadProfiles) ? policy.requiredLoadProfiles : [50, 100, 500];
  const profiles = load?.payload?.profiles ?? [];
  const missingProfiles = requiredProfiles.filter((users) => !profiles.some((profile) => Number(profile.users) === Number(users)));
  const failedProfiles = profiles.filter((profile) => Number(profile.metric?.errors ?? 0) !== 0 || Number(profile.metric?.p95 ?? 0) > Number(profile.metric?.maxP95Ms ?? 0));
  const loadTarget = load?.payload?.target ?? {};
  const publicLoadTarget = !policy.requirePublicLoadTarget || (loadTarget.public === true && publicEvidenceUrl(load?.payload?.url));
  const loadEdgeEvidence = !policy.requireLoadEdgeEvidence || (
    loadTarget.edgeRequired === true
    && loadTarget.edge?.providerMatched === true
    && Boolean(loadTarget.edge?.provider)
  );
  addGoNoGoCheck(checks, {
    name: "public-load-benchmark",
    passed: Boolean(load && loadFresh.fresh && load.payload.status === "passed" && missingProfiles.length === 0 && failedProfiles.length === 0 && publicLoadTarget && loadEdgeEvidence),
    detail: load
      ? `${loadFresh.detail}; status=${load.payload.status ?? "unknown"}; missingProfiles=${missingProfiles.join(",") || "none"}; failedProfiles=${failedProfiles.map((profile) => profile.users).join(",") || "none"}; publicTarget=${publicLoadTarget ? "yes" : "no"}; edgeEvidence=${loadEdgeEvidence ? loadTarget.edge?.provider ?? "not-required" : "missing"}`
      : latestLoadReport
        ? `missing public edge benchmark report; latestUrl=${latestLoadReport.payload.url ?? "unknown"}; ${latestLoadFresh.detail}`
        : loadFresh.detail,
    report: load ?? latestLoadReport,
  });

  const latestReleaseReport = latestJsonReport("release", "release-evidence-");
  const release = latestJsonReport("release", "release-evidence-", (payload) => payload.mode === "evidence");
  const releaseFresh = reportFreshDetail(release, maxAge.release);
  const latestReleaseFresh = reportFreshDetail(latestReleaseReport, maxAge.release);
  const releasePayload = release?.payload ?? {};
  const releaseProvenanceOk = !policy.requireReleaseProvenance || Boolean(
    releasePayload.artifacts?.provenance
      && releasePayload.attestations?.provenanceRequired
      && releasePayload.attestations?.slsaProvenance?.status === "passed"
      && releasePayload.attestations?.slsaProvenance?.releaseShaMatched !== false,
  );
  const releaseGitOk = !policy.requireCleanReleaseGit || releasePayload.git?.dirty === false;
  const releaseRollbackOk = Boolean(
    releasePayload.rollback?.complete
      && (releasePayload.rollback?.firstDeploy || releasePayload.rollback?.dryRun?.validated === true),
  );
  addGoNoGoCheck(checks, {
    name: "release-evidence-and-rollback",
    passed: Boolean(release && releaseFresh.fresh && releasePayload.mode === "evidence" && releasePayload.status === "passed" && releaseRollbackOk && releasePayload.artifacts?.sbom && releaseProvenanceOk && releaseGitOk),
    detail: release
      ? `${releaseFresh.detail}; mode=${releasePayload.mode}; status=${releasePayload.status ?? "unknown"}; rollback=${releaseRollbackOk ? "validated" : "missing"}; provenance=${releaseProvenanceOk ? "yes" : "no"}; cleanGit=${releaseGitOk ? "yes" : "no"}`
      : latestReleaseReport
        ? `missing evidence report; latestReleaseMode=${latestReleaseReport.payload.mode ?? "unknown"}; latestStatus=${latestReleaseReport.payload.status ?? "unknown"}; ${latestReleaseFresh.detail}`
        : releaseFresh.detail,
    report: release ?? latestReleaseReport,
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
  addGoNoGoCheck(checks, {
    name: "cloudflare-access-admin-verified",
    passed: Boolean(cloudflareAccess && cloudflareAccessFresh.fresh && cloudflareAccess.payload.status === "passed" && cloudflareVerified),
    detail: cloudflareAccess
      ? `${cloudflareAccessFresh.detail}; mode=${cloudflareAccess.payload.mode}; verified=${cloudflareVerified ? "yes" : "no"}`
      : latestCloudflareAccessReport
        ? `missing verifyRemote report; latestMode=${latestCloudflareAccessReport.payload.mode ?? "unknown"}; latestStatus=${latestCloudflareAccessReport.payload.status ?? "unknown"}; ${latestCloudflareAccessFresh.detail}`
        : cloudflareAccessFresh.detail,
    report: cloudflareAccess ?? latestCloudflareAccessReport,
  });

  const failedRequired = checks.filter((check) => check.required && check.status !== "passed");
  const status = failedRequired.length ? "no-go" : "go";
  const generatedAt = new Date().toISOString();
  const remediation = failedRequired.map(goNoGoRemediation);
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
    checks,
    failedRequired: failedRequired.map((check) => check.name),
    remediation,
    report,
  };
  const jsonPath = writeJsonReport("go-no-go", baseName, payload);
  const markdownPath = writeMarkdownReport("go-no-go", baseName, [
    "# Stexor Production Go/No-Go",
    "",
    `Status: ${status}`,
    `Mode: ${payload.mode}`,
    `Generated at: ${generatedAt}`,
    `Policy: ${policyPath}`,
    "",
    "| Check | Status | Detail | Report |",
    "| --- | --- | --- | --- |",
    ...checks.map((check) => `| ${check.name} | ${check.status} | ${check.detail.replace(/\|/g, "/")} | ${check.reportPath ?? "n/a"} |`),
    "",
    "## Failed Required Checks",
    "",
    ...(failedRequired.length ? failedRequired.map((check) => `- ${check.name}`) : ["- none"]),
    "",
    "## Remediation Checklist",
    "",
    ...goNoGoRemediationMarkdown(remediation),
  ]);
  log(`Production go/no-go report written to ${jsonPath} and ${markdownPath}`);
  log(`Production status: ${status}`);
  if (enforce && failedRequired.length) {
    fail(`Production no-go: ${failedRequired.map((check) => check.name).join(", ")}. Report: ${jsonPath}`);
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
    const shellScript = 'for file in scripts/*.sh; do sh -n "$file"; done';
    const canUseContainerShell = process.env.STEXOR_OPS_CONTAINER === "1" || fs.existsSync("/.dockerenv");
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
    "# Stexor Linux Portability Check",
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
    ["root-policy", /^(?:\.env(?:\..*)?|\.gitattributes|\.gitignore|renovate\.json|SECURITY\.md|THREAT-MODEL\.md)$/],
    ["object-storage", /^minio\//],
    ["documentation", /^(?:README|RUNBOOK|ENTERPRISE-10-PLAN|ENTERPRISE-MATURITY|FINAL-READINESS-AUDIT|READINESS-REPORT|VPS-PREDEPLOY-CHECKLIST)\.md$|^(?:cloudflare|keycloak|minio|secrets)\/README\.md$/],
    ["compose", /^compose(?:\.[^.]+)?\.ya?ml$/],
    ["docker-build", /^docker\/[^/]+\.Dockerfile$/],
    ["operations-script", /^scripts\/.+\.(?:sh|mjs)$/],
    ["governance-policy", /^governance\/.+\.json$/],
    ["cloudflare-policy", /^cloudflare\/.+\.(?:json|md)$/],
    ["observability", /^(?:alertmanager|grafana|loki|monitoring|prometheus|promtail)\//],
    ["identity", /^keycloak\//],
    ["database", /^(?:postgres|mariadb)\//],
    ["messaging", /^nats\//],
    ["php-runtime", /^(?:php-apache|phpmyadmin)\//],
    ["reverse-proxy", /^traefik\//],
    ["waf", /^waf\//],
    ["security-policy", /^security\//],
  ];
  const match = rules.find(([, pattern]) => pattern.test(normalized));
  return match?.[0] ?? null;
}

async function repoCoverageCheck() {
  log("==> Repository coverage check");
  const trackedFiles = output("git", ["ls-files"], { cwd: infraRoot })
    .split(/\r?\n/)
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
  const workflow = readText(path.join(infraRoot, ".github", "workflows", "enterprise-infra.yml"));
  const requiredWorkflowGates = [
    ["local-compose-render", /Render local WAF compose[\s\S]*compose\.yaml[\s\S]*compose\.build\.yaml[\s\S]*compose\.secrets\.yaml[\s\S]*compose\.waf\.yaml/],
    ["hostinger-compose-render", /Render Hostinger WAF compose[\s\S]*compose\.hostinger\.yaml[\s\S]*compose\.hostinger-waf\.yaml/],
    ["staging-compose-render", /Render staging and backup compose[\s\S]*compose\.waf\.yaml[\s\S]*compose\.staging\.yaml/],
    ["backup-compose-render", /Render staging and backup compose[\s\S]*compose\.backup-scheduler\.yaml/],
    ["backup-scheduler-dry-run", /Backup scheduler dry run[\s\S]*BACKUP_SCHEDULER_DRY_RUN=true/],
    ["external-uptime-dry-run", /external-uptime-check --dryRun/],
    ["cloudflare-access-dry-run", /cloudflare-access-admin --manifest cloudflare\/access-admin\.example\.json/],
    ["cloudflare-from-zero-dry-run", /Cloudflare from-zero dry run[\s\S]*cloudflare-from-zero --manifest cloudflare\/from-zero\.example\.json/],
    ["github-branch-policy-dry-run", /github-branch-protection --repo/],
    ["github-environments-dry-run", /github-environments --repo/],
    ["github-actions-runtime-dry-run", /github-actions-config --repo/],
    ["github-actions-run-evidence-plan", /GitHub Actions run evidence plan[\s\S]*github-actions-run-evidence/],
    ["secret-scan", /Secret scan[\s\S]*secret-scan/],
    ["ha-config-check", /HA configuration check[\s\S]*ha-config-check/],
    ["managed-secrets-preflight", /Managed secrets preflight[\s\S]*managed-secrets-preflight/],
    ["secret-rotation-evidence-plan", /Secret rotation evidence plan[\s\S]*secret-rotation-evidence/],
    ["dr-readiness-check", /DR readiness check[\s\S]*dr-readiness-check/],
    ["dr-evidence-summary", /DR evidence summary[\s\S]*dr-evidence/],
    ["offsite-restore-plan", /Off-site restore drill plan[\s\S]*offsite-restore-drill-restic --planOnly/],
    ["release-evidence-plan", /release-evidence --planOnly/],
    ["release-artifact-gate-dry-run", /Release artifact gate dry run[\s\S]*release-artifact-gate --envFile \.tmp\/ci-release\.env --sbom \.tmp\/ci-sbom\/pnpm-sbom-ci\.json/],
    ["alert-evidence-summary", /alert-evidence/],
    ["production-go-no-go-summary", /production-go-no-go/],
    ["pre-go-live-evidence-report", /Pre go-live evidence report[\s\S]*pre-go-live-evidence --infraOnly --repo/],
    ["evidence-bundle-smoke", /evidence-bundle --noArchive/],
    ["evidence-bundle-verify", /Evidence bundle integrity verify[\s\S]*evidence-bundle-verify/],
    ["linux-portability", /linux-portability-check/],
    ["enterprise-requirements", /Enterprise requirements traceability[\s\S]*enterprise-requirements-check/],
    ["production-readiness-checklist", /Production readiness checklist[\s\S]*enterprise-requirements-check --manifest governance\/production-readiness\.json/],
    ["production-live-proof-rejection", /Production live proof gate rejects missing evidence[\s\S]*enterprise-requirements-check --manifest governance\/production-readiness\.json --requireLiveProofs/],
    ["static-security-infra-only", /static-security-check --infraOnly/],
    ["repository-coverage", /repo-coverage-check/],
    ["ci-evidence-artifact", /Upload CI evidence reports[\s\S]*actions\/upload-artifact@v4[\s\S]*reports\/[\s\S]*\.tmp\/evidence-bundles\/[\s\S]*retention-days:\s+30/],
    ["least-privilege-permissions", /permissions:\s*\r?\n\s+contents:\s+read(?![\s\S]*security-events:\s+write)/],
    ["compose-job-timeout", /compose-and-policy:[\s\S]*timeout-minutes:\s+45/],
    ["shell-job-timeout", /shell-syntax:[\s\S]*timeout-minutes:\s+10/],
    ["dast-job-timeout", /dast-zap:[\s\S]*timeout-minutes:\s+45/],
    ["deploy-job-timeout", /deploy-hostinger:[\s\S]*timeout-minutes:\s+90/],
    ["shell-syntax", /for file in scripts\/\*\.sh/],
    ["workflow-dispatch", /workflow_dispatch:/],
    ["dast-manual", /dast-zap:[\s\S]*dast-zap-baseline\.sh/],
    ["deploy-manual", /deploy-hostinger:[\s\S]*deploy-hostinger\.sh/],
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
  const go = goNoGoReport.payload.status === "go";
  const passed = go && allChecksPassed;
  return {
    required: true,
    status: passed ? "passed" : requireLiveProofs ? "failed" : "pending-external-evidence",
    detail: passed
      ? "production go/no-go report proves mapped checks"
      : `production go/no-go status=${goNoGoReport.payload.status ?? "unknown"}; failedOrMissing=${checkResults.filter((check) => check.status !== "passed").map((check) => check.name).join(",") || "none"}`,
    checks: checkResults,
    reportPath: goNoGoReport.filePath,
  };
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
  const workflowText = readText(path.join(infraRoot, ".github", "workflows", "enterprise-infra.yml"));
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
  await haConfigCheck();
  await managedSecretsPreflight();
  await releaseArtifactGate();
  await drReadinessCheck();
  await governanceCheck();
  await externalUptimeCheck({ dryRun: true });
  await linuxPortabilityCheck();
  await staticSecurityCheck();
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
  const database = argv.database ?? "stexor_app";
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
    log("Restore complete.");
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
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? "stexor_app";
  const testDatabase = options.testDatabase ?? argv.testDatabase ?? "stexor_restore_test";
  const user = options.user ?? argv.user ?? "postgres";
  const backupFile = resolveInside(path.join(infraRoot, "backups"), path.resolve(backupFileArg));
  const fileName = path.basename(backupFile);
  const containerPath = `/tmp/${fileName}`;
  const startedAt = new Date();
  const { hash } = verifyBackupArtifact(backupFile);
  const testDatabaseIdentifier = sqlIdentifier(testDatabase);
  try {
    log(`Creating disposable restore-test database '${testDatabase}'...`);
    dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `drop database if exists ${testDatabaseIdentifier} with (force);`]);
    dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `create database ${testDatabaseIdentifier};`]);
    run("docker", ["cp", backupFile, `${container}:${containerPath}`]);
    dockerExec(container, ["pg_restore", "-U", user, "-d", testDatabase, "--no-owner", "--no-acl", containerPath]);
    dockerExec(container, ["rm", "-f", containerPath]);
    const tables = Number(postgresOut(container, testDatabase, user, "select count(*) from information_schema.tables where table_schema = 'stexor_account';"));
    dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `drop database if exists ${testDatabaseIdentifier} with (force);`]);
    if (tables < 10) {
      fail(`Restore test produced too few stexor_account tables: ${tables}`);
    }
    recordBackupRestoreRun({ container, database, user, operation: "restore_test", status: "success", artifactPath: backupFile, artifactSha256: hash, startedAt, metadata: { restoredTables: tables, testDatabase } });
    log(`Restore test passed with ${tables} stexor_account tables.`);
    return { backupFile, hash, tables, testDatabase, container, database, user };
  } catch (error) {
    try {
      dockerExec(container, ["rm", "-f", containerPath], { allowFailure: true });
      dockerExec(container, ["psql", "-U", user, "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-c", `drop database if exists ${testDatabaseIdentifier} with (force);`], { allowFailure: true });
      recordBackupRestoreRun({ container, database, user, operation: "restore_test", status: "failed", artifactPath: backupFile, artifactSha256: hash, startedAt, metadata: { error: String(error?.message ?? error), testDatabase } });
    } catch {
      // Preserve the original restore-test failure.
    }
    throw error;
  }
}

async function backupRestoreDrill() {
  log("==> PostgreSQL backup/restore drill");
  const container = argv.container ?? "enterprise-postgres";
  const database = argv.database ?? "stexor_app";
  const user = argv.user ?? "postgres";
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "postgres", "drills"));
  const suffix = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const testDatabase = argv.testDatabase ?? `stexor_restore_test_${suffix}`;
  const backup = await backupPostgres({ container, database, user, outputDir });
  const restore = await restoreTestPostgres({ container, database, user, backupFile: backup.hostPath, testDatabase });
  const recorded = postgresOut(
    container,
    database,
    user,
    `
      select count(*)
      from stexor_platform.backup_restore_runs
      where operation = 'restore_test'
        and status = 'success'
        and artifact_sha256 = ${sqlString(backup.hash)}
        and metadata->>'testDatabase' = ${sqlString(restore.testDatabase)}
    `,
  ).trim();
  if (recorded !== "1") {
    fail("Restore drill completed but backup_restore_runs did not record the matching restore_test success.");
  }
  log(`Backup/restore drill recorded restore_test success for ${path.basename(backup.hostPath)}.`);
}

async function backupMariadb(options = {}) {
  const container = options.container ?? argv.container ?? "mariadb";
  const outputDir = ensureBackupOutputDir(path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "mariadb")));
  const startedAt = new Date();
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "-");
  const fileName = `mariadb-all-${timestamp}.sql.gz`;
  const containerPath = `/tmp/${fileName}`;
  const hostPath = path.join(outputDir, fileName);

  try {
    log("Creating MariaDB full backup for all local PHP project databases...");
    dockerExec(container, [
      "sh",
      "-ec",
      [
        "test -s /run/secrets/mariadb_root_password",
        'MARIADB_ROOT_PASSWORD="$(cat /run/secrets/mariadb_root_password)"',
        'DATABASES="$(mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" -N -e "select schema_name from information_schema.schemata where schema_name not in (\'information_schema\',\'mysql\',\'performance_schema\',\'sys\') order by schema_name")"',
        'test -n "$DATABASES"',
        `mariadb-dump --single-transaction --routines --events --triggers --databases $DATABASES -uroot -p"$MARIADB_ROOT_PASSWORD" | gzip -9 > ${shellQuote(containerPath)}`,
      ].join(" && "),
    ]);
    run("docker", ["cp", `${container}:${containerPath}`, hostPath]);
    dockerExec(container, ["rm", "-f", containerPath]);

    const hash = sha256File(hostPath);
    fs.writeFileSync(`${hostPath}.sha256`, `${hash}  ${fileName}\n`, "ascii");
    const signature = signBackupArtifact(hostPath, hash);
    recordDatabaseBackupEvidence({
      engine: "mariadb",
      sourceContainer: container,
      operation: "backup",
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
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
      metadata: { scope: "all-user-databases", compression: "gzip" },
    });
    log(`MariaDB backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, container };
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
  const drillContainer = options.drillContainer ?? argv.drillContainer ?? `stexor-mariadb-restore-test-${suffix}`;
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

async function backupRestoreDrillMariadb() {
  log("==> MariaDB backup/restore drill");
  const container = argv.container ?? "mariadb";
  const outputDir = path.resolve(argv.outputDir ?? path.join(infraRoot, "backups", "mariadb", "drills"));
  const backup = await backupMariadb({ container, outputDir });
  await restoreTestMariadb({ container, backupFile: backup.hostPath });
  log(`MariaDB backup/restore drill completed for ${path.basename(backup.hostPath)}.`);
}

async function backupMinio(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-minio";
  const outputDir = ensureBackupOutputDir(path.resolve(options.outputDir ?? argv.outputDir ?? path.join(infraRoot, "backups", "minio")));
  const startedAt = new Date();
  const fileName = `minio-data-${backupTimestamp()}.tar.gz`;
  const hostPath = path.join(outputDir, fileName);
  const hostWorkParent = makeOpsTempDir("stexor-minio-data-");
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
      `tar -czf /backup/${shellQuote(fileName)} -C /work .`,
    ]);

    const { hash, signature } = writeBackupIntegritySidecars(hostPath);
    recordDatabaseBackupEvidence({
      engine: "minio",
      sourceContainer: container,
      operation: "backup",
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
      startedAt,
    });
    writeBackupExecutionReport({
      engine: "minio",
      sourceContainer: container,
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
      signature,
      startedAt,
      metadata: { scope: "data-volume", compression: "tar.gz" },
    });
    log(`MinIO backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, container };
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
  const drillContainer = options.drillContainer ?? argv.drillContainer ?? `stexor-minio-restore-test-${suffix}`;
  const drillVolume = options.drillVolume ?? argv.drillVolume ?? `stexor_minio_restore_test_${suffix}`;
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
  const containerWorkDir = "/tmp/stexor-keycloak-config-backup";
  const hostWorkParent = makeOpsTempDir("stexor-keycloak-config-");
  const hostWorkDir = path.join(hostWorkParent, "keycloak-config");
  const backupScript = `
set -eu
work="${containerWorkDir}"
rm -rf "$work"
mkdir -p "$work/realms" "$work/import" "$work/runtime"
KC_BOOTSTRAP_ADMIN_PASSWORD="$(cat /run/secrets/keycloak_admin_password)"
export KC_BOOTSTRAP_ADMIN_PASSWORD
/opt/keycloak/bin/kcadm.sh config credentials --server http://127.0.0.1:8080 --realm master --user "$KC_BOOTSTRAP_ADMIN_USERNAME" --password "$KC_BOOTSTRAP_ADMIN_PASSWORD" >/tmp/stexor-kcadm-backup.log 2>&1
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
      `tar -czf /backup/${shellQuote(fileName)} -C /work .`,
    ]);

    const { hash, signature } = writeBackupIntegritySidecars(hostPath);
    recordDatabaseBackupEvidence({
      engine: "keycloak",
      sourceContainer: container,
      operation: "backup",
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
      startedAt,
    });
    writeBackupExecutionReport({
      engine: "keycloak",
      sourceContainer: container,
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
      signature,
      startedAt,
      metadata: { scope: "configuration", compression: "tar.gz" },
    });
    log(`Keycloak config backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash, container };
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
  const workDir = makeOpsTempDir("stexor-secret-manager-metadata-");

  try {
    const files = [
      ["stexor-secret-manager-store.json", path.join(infraRoot, "secrets", "stexor-secret-manager-store.json")],
      ["stexor-secret-manager-audit.log", path.join(infraRoot, "secrets", "stexor-secret-manager-audit.log")],
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
      "Stexor Secret Manager metadata backup.",
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
      `tar -czf /backup/${shellQuote(fileName)} -C /work .`,
    ]);
    const { hash, signature } = writeBackupIntegritySidecars(hostPath);
    recordDatabaseBackupEvidence({
      engine: "secret-manager",
      sourceContainer: "host-metadata",
      operation: "backup",
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
      startedAt,
    });
    writeBackupExecutionReport({
      engine: "secret-manager",
      sourceContainer: "host-metadata",
      status: "success",
      artifactPath: hostPath,
      artifactSha256: hash,
      signature,
      startedAt,
      metadata: { scope: "metadata-without-master-key", compression: "tar.gz" },
    });
    log(`Secret Manager metadata backup written to ${hostPath}`);
    log(`SHA256: ${hash}`);
    log(`Signature: ${signature.signaturePath} (${signature.keyId})`);
    return { hostPath, hash };
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
        "test -s \"$work/stexor-secret-manager-store.json\"",
        "grep -q '\"manager\": \"stexor-secret-manager\"' \"$work/stexor-secret-manager-store.json\"",
        "grep -q '\"provider\": \"stexor-local-kms\"' \"$work/stexor-secret-manager-store.json\"",
        "test ! -e \"$work/stexor-secret-manager-master.key\"",
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
  log("==> Full Stexor restore drill");
  const startedAt = new Date();
  const steps = [
    ["postgres", backupRestoreDrill],
    ["mariadb", backupRestoreDrillMariadb],
    ["minio", backupRestoreDrillMinio],
    ["keycloak", backupRestoreDrillKeycloakConfig],
    ["secret-manager-metadata", backupRestoreDrillSecretManagerMetadata],
  ];
  const results = [];
  for (const [name, fn] of steps) {
    const stepStarted = Date.now();
    await fn();
    results.push({ name, durationMs: Date.now() - stepStarted, status: "success" });
  }
  const healthStarted = Date.now();
  await infraHealth();
  results.push({ name: "infra-health", durationMs: Date.now() - healthStarted, status: "success" });
  const finishedAt = new Date();
  const payload = {
    generatedAt: finishedAt.toISOString(),
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    steps: results,
  };
  const stamp = reportTimestamp();
  const jsonPath = writeJsonReport("restore-drills", `full-restore-drill-${stamp}`, payload);
  const markdownPath = writeMarkdownReport("restore-drills", `full-restore-drill-${stamp}`, [
    "# Stexor Full Restore Drill",
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

  const latestOffsiteDryRun = latestReport(offsiteRestoreReports, (report) => report.status === "success" && report.mode === "dry-run");
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
    issues.push(`Latest off-site restore drill does not prove full data-family coverage. Missing: ${latestOffsiteRestoreCoverage?.missingRequiredFamilies?.join(", ") || "unknown"}.`);
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
    "# Stexor DR Evidence",
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
    `Latest full restore missing families: ${payload.offsiteEvidence.latestRestoreCoverage?.missingRequiredFamilies?.join(", ") || "none"}`,
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

function assertRecentRestoreTest(container, database, user, maxAgeDays) {
  const count = postgresOut(
    container,
    database,
    user,
    `
      select count(*)
      from stexor_platform.backup_restore_runs
      where operation = 'restore_test'
        and status = 'success'
        and finished_at >= now() - (${positiveInteger(maxAgeDays, "--maxRestoreTestAgeDays")}::text || ' days')::interval
    `,
  ).trim();
  if (count === "0") {
    fail(`Refusing backup retention cleanup: no successful restore_test in the last ${maxAgeDays} days.`);
  }
}

async function prunePostgresBackups(options = {}) {
  const container = options.container ?? argv.container ?? "enterprise-postgres";
  const database = options.database ?? argv.database ?? "stexor_app";
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
  log(`Retention complete: regular ${backups.pruned}/${backups.total} pruned, drill ${drills.pruned}/${drills.total} pruned.`);
}

async function secretScan() {
  const roots = [
    path.resolve(argv.infraRoot ?? infraRoot),
    path.resolve(argv.sourceRoot ?? sourceRoot),
  ];
  const patterns = [
    /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\b(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\b\s*[:=]\s*['"]?[A-Za-z0-9/+]{32,}/,
    /\b(api|access|secret|private|client)_?(key|token|secret)\b\s*[:=]\s*['"][^'"]{16,}/i,
    /\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{8,}/i,
    /\bSMTP_PASSWORD\b\s*=.+/i,
  ];
  const ignoredDirs = new Set([
    ".git",
    ".tmp",
    "node_modules",
    ".pnpm-store",
    ".next",
    "dist",
    "coverage",
    "backups",
    "release",
    "reports",
    "secrets",
    "certs",
    "acme",
    "sbom",
  ]);
  const hits = [];
  const scanFile = (filePath) => {
    const relativeName = path.basename(filePath);
    if (/^\.env(?:\.|$)/.test(relativeName)) {
      return;
    }
    const stat = fs.statSync(filePath);
    if (stat.size > 2 * 1024 * 1024) {
      return;
    }
    const content = fs.readFileSync(filePath);
    if (content.includes(0)) {
      return;
    }
    const text = content.toString("utf8");
    const lines = text.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (/change_me|placeholder|example|your-domain|smtpPassword|redisPassword|dbPassword|rootPassword|WITH PASSWORD :'\w+_password'/i.test(line)) {
        return;
      }
      if (patterns.some((pattern) => pattern.test(line))) {
        hits.push(`${filePath}:${index + 1}: ${line.trim()}`);
      }
    });
  };
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ignoredDirs.has(entry.name)) {
        continue;
      }
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        scanFile(fullPath);
      }
    }
  };
  for (const root of roots) {
    if (fs.existsSync(root)) {
      walk(root);
    }
  }
  if (hits.length) {
    hits.forEach((hit) => log(hit));
    fail("Potential hardcoded secrets found. Review the hits above.");
  }
  log("Secret scan passed.");
}

async function securitySmoke() {
  const env = parseEnv(path.join(infraRoot, ".env"));
  const uiPublicUrl = env.UI_PUBLIC_URL ?? env.NEXT_PUBLIC_UI_URL ?? "https://ui.localhost.com";
  const accountPublicUrl = env.ACCOUNT_PUBLIC_URL ?? env.NEXT_PUBLIC_ACCOUNT_URL ?? "https://account.localhost.com";
  const apiPublicUrl = env.API_PUBLIC_URL ?? env.NEXT_PUBLIC_API_URL ?? "https://api.localhost.com";
  const defaultUrls = [
    `${uiPublicUrl.replace(/\/$/, "")}/`,
    `${accountPublicUrl.replace(/\/$/, "")}/`,
    `${apiPublicUrl.replace(/\/$/, "")}/health`,
  ].join(",");
  const urls = (argv.urls ?? defaultUrls).split(",").map((url) => url.trim()).filter(Boolean);
  for (const url of urls) {
    log(`Checking ${url}`);
    const response = await request("HEAD", url);
    const headers = headerText(response.headers);
    for (const required of ["strict-transport-security", "x-content-type-options", "referrer-policy", "permissions-policy"]) {
      if (!headers.includes(required)) {
        fail(`Missing ${required} on ${url}`);
      }
    }
  }

  assertStatus(await request("GET", "https://api.localhost.com/account/snapshot"), 401, "unauthenticated account snapshot");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { Origin: "https://evil.example" } }), 403, "untrusted Origin");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { "Sec-Fetch-Site": "cross-site" } }), 403, "cross-site Fetch Metadata");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" } }), 200, "same-site logout");
  assertStatus(await request("POST", "https://api.localhost.com/auth/logout", { headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "cross-site" } }), 200, "trusted cross-site logout");
  log("Security smoke checks passed.");
}

async function wafSmoke() {
  const apiBase = (argv.apiBase ?? "https://api.localhost.com").replace(/\/$/, "");
  const phpBase = (argv.phpBase ?? "https://projects.localhost.com").replace(/\/$/, "");
  const smokeHeaders = { "User-Agent": "stexor-waf-smoke/1.0" };
  log("==> WAF smoke checks");

  assertStatus(await request("GET", `${apiBase}/health`, { headers: smokeHeaders }), 200, "WAF pass-through health");
  const sqlInjection = await request("GET", `${apiBase}/health?search=%27%20OR%201%3D1--`, { headers: smokeHeaders });
  if (![403, 406].includes(sqlInjection.status)) {
    fail(`WAF SQL injection probe expected HTTP 403/406, got ${sqlInjection.status}: ${sqlInjection.text}`);
  }

  const xssProbe = await request("GET", `${apiBase}/health?x=%3Cscript%3Ealert(1)%3C/script%3E`, { headers: smokeHeaders });
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
}

async function infraHealth() {
  const defaultContainers = [
    "enterprise-traefik",
    "enterprise-waf",
    "enterprise-web",
    "enterprise-backend",
    "enterprise-worker-notifications",
    "enterprise-worker-jobs",
    "mariadb",
    "enterprise-postgres",
    "enterprise-redis",
    "enterprise-nats",
    "enterprise-keycloak",
    "enterprise-minio",
    "enterprise-grafana",
    "enterprise-prometheus",
    "enterprise-node-exporter",
    "enterprise-cadvisor",
    "enterprise-loki",
    "enterprise-alertmanager",
    "enterprise-promtail",
  ];
  const containers = (argv.containers ? String(argv.containers).split(",") : defaultContainers)
    .map((container) => container.trim())
    .filter(Boolean);
  const apiBase = (argv.apiBase ?? "https://api.localhost.com").replace(/\/$/, "");
  const uiBase = (argv.uiBase ?? "https://ui.localhost.com").replace(/\/$/, "");
  const accountBase = (argv.accountBase ?? "https://account.localhost.com").replace(/\/$/, "");
  const projectsBase = (argv.projectsBase ?? "https://projects.localhost.com").replace(/\/$/, "");
  const useAdminHostnames = process.env.STEXOR_OPS_CONTAINER === "1" || booleanFlag(argv.adminHostnames);
  const adminBlockUrl = (host, requestPath = "/") => (
    useAdminHostnames ? `https://${host}${requestPath}` : `https://127.0.0.1${requestPath}`
  );
  const adminBlockHeaders = (host) => (useAdminHostnames ? {} : { Host: host });
  const checks = [];
  const addCheck = (name, ok, detail = "") => {
    checks.push({ name, ok, detail });
  };

  log("==> Infra health");
  for (const container of containers) {
    const inspect = run("docker", [
      "inspect",
      "--format",
      "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
      container,
    ], { allowFailure: true, capture: true });
    if (inspect.status !== 0) {
      addCheck(`container:${container}`, false, "not found");
      continue;
    }
    const [status, health = "none"] = String(inspect.stdout ?? "").trim().split("|");
    const ok = status === "running" && (health === "none" || health === "healthy");
    addCheck(`container:${container}`, ok, `status=${status || "unknown"} health=${health || "none"}`);
  }

  const httpChecks = [
    { name: "api-health", method: "GET", url: `${apiBase}/health`, statuses: [200] },
    { name: "ui-home", method: "HEAD", url: `${uiBase}/`, statuses: [200, 308] },
    { name: "account-home", method: "HEAD", url: `${accountBase}/`, statuses: [200, 308] },
    { name: "projects-gateway", method: "GET", url: `${projectsBase}/`, statuses: [200], body: /Projects Access|Permanent session|Admin e database/ },
    { name: "grafana-login", method: "GET", url: "https://grafana.localhost.com/login", statuses: [200] },
    { name: "admin-traefik-block", method: "GET", url: adminBlockUrl("traefik.localhost.com", "/dashboard/"), statuses: [403, 404], headers: adminBlockHeaders("traefik.localhost.com") },
    { name: "admin-prometheus-block", method: "GET", url: adminBlockUrl("prometheus.localhost.com"), statuses: [403, 404], headers: adminBlockHeaders("prometheus.localhost.com") },
    { name: "admin-alertmanager-block", method: "GET", url: adminBlockUrl("alertmanager.localhost.com"), statuses: [403, 404], headers: adminBlockHeaders("alertmanager.localhost.com") },
    { name: "waf-xss-block", method: "GET", url: `${apiBase}/health?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E`, statuses: [403, 406] },
    { name: "waf-sensitive-file-block", method: "GET", url: `${projectsBase}/.env`, statuses: [403, 404] },
  ];
  for (const check of httpChecks) {
    const started = Date.now();
    try {
      const response = await request(check.method, check.url, { headers: { "User-Agent": "stexor-infra-health/1.0", ...(check.headers ?? {}) } });
      const latencyMs = Date.now() - started;
      const statusOk = check.statuses.includes(response.status);
      const bodyOk = !check.body || check.body.test(response.text);
      addCheck(`http:${check.name}`, statusOk && bodyOk, `status=${response.status} latencyMs=${latencyMs}`);
    } catch (error) {
      addCheck(`http:${check.name}`, false, String(error?.message ?? error));
    }
  }

  if (booleanFlag(argv.json)) {
    log(JSON.stringify({ ok: checks.every((check) => check.ok), checks }, null, 2));
  } else {
    for (const check of checks) {
      log(`${check.ok ? "OK  " : "FAIL"} ${check.name}${check.detail ? ` - ${check.detail}` : ""}`);
    }
  }
  const failures = checks.filter((check) => !check.ok);
  if (failures.length) {
    fail(`Infra health failed: ${failures.map((failure) => failure.name).join(", ")}`);
  }
  log("Infra health passed.");
}

async function signImages() {
  const images = (argv.images ? argv.images.split(",") : [
    process.env.BACKEND_IMAGE,
    process.env.WEB_IMAGE,
    process.env.WORKER_NOTIFICATIONS_IMAGE,
    process.env.WORKER_JOBS_IMAGE,
  ]).filter(Boolean);
  const key = argv.key ?? process.env.COSIGN_KEY;
  const hasCosign = run("cosign", ["version"], { capture: true, allowFailure: true }).status === 0;
  if (!hasCosign) {
    fail("cosign is required for image signing. Install cosign and authenticate to your registry.");
  }
  if (!key) {
    fail("Set COSIGN_KEY to a key reference or use keyless signing in CI.");
  }
  for (const image of images) {
    if (/:latest$/.test(image)) {
      fail(`Refusing to sign mutable :latest image: ${image}`);
    }
    run("cosign", ["sign", "--key", key, image]);
  }
  log("Image signing completed.");
}

function staticSecurityInfraOnlyCheck() {
  log("==> Static security checks (infra-only)");
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const composeBuild = readText(path.join(infraRoot, "compose.build.yaml"));
  const composeSecrets = readText(path.join(infraRoot, "compose.secrets.yaml"));
  const composeWaf = readText(path.join(infraRoot, "compose.waf.yaml"));
  const composeHostingerWaf = readText(path.join(infraRoot, "compose.hostinger-waf.yaml"));
  const phpApacheDockerfile = readText(path.join(infraRoot, "docker", "php-apache.Dockerfile"));
  const opsDockerfile = readText(path.join(infraRoot, "docker", "ops.Dockerfile"));
  const opsWrapper = readText(path.join(infraRoot, "scripts", "stexor-ops.sh"));
  const backupSchedulerScript = readText(path.join(infraRoot, "scripts", "backup-scheduler.sh"));
  const evidenceBundleVerifyWrapper = readText(path.join(infraRoot, "scripts", "evidence-bundle-verify.sh"));
  const githubActionsRunEvidenceWrapper = readText(path.join(infraRoot, "scripts", "github-actions-run-evidence.sh"));
  const secretRotationEvidenceWrapper = readText(path.join(infraRoot, "scripts", "secret-rotation-evidence.sh"));
  const opsScript = readText(path.join(infraRoot, "scripts", "stexor-ops.mjs"));
  const hostingerPostdeployScript = readText(path.join(infraRoot, "scripts", "hostinger-postdeploy.sh"));
  const productionReadinessLiveWrapper = readText(path.join(infraRoot, "scripts", "production-readiness-live.sh"));
  const githubWorkflow = readText(path.join(infraRoot, ".github", "workflows", "enterprise-infra.yml"));
  const readme = readText(path.join(infraRoot, "README.md"));
  const runbook = readText(path.join(infraRoot, "RUNBOOK.md"));
  const envExample = readText(path.join(infraRoot, ".env.example"));
  const productionReadinessManifest = readText(path.join(infraRoot, "governance", "production-readiness.json"));
  const productionGoNoGoPolicyText = readText(path.join(infraRoot, "governance", "production-go-no-go.json"));
  const infraRenovate = readText(path.join(infraRoot, "renovate.json"));
  const infraGitattributes = readText(path.join(infraRoot, ".gitattributes"));
  const gitignore = readText(path.join(infraRoot, ".gitignore"));
  const localWafPreRules = readText(path.join(infraRoot, "waf", "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"));
  const hostingerWafPreRules = readText(path.join(infraRoot, "waf", "REQUEST-900-HOSTINGER-RULES-BEFORE-CRS.conf"));
  const phpMyAdminConfig = readText(path.join(infraRoot, "phpmyadmin", "config.user.inc.php"));

  const infrastructureText = [
    compose,
    composeBuild,
    composeSecrets,
    composeWaf,
    composeHostingerWaf,
    phpApacheDockerfile,
    opsDockerfile,
    opsWrapper,
    backupSchedulerScript,
    evidenceBundleVerifyWrapper,
    githubActionsRunEvidenceWrapper,
    secretRotationEvidenceWrapper,
    hostingerPostdeployScript,
    productionReadinessLiveWrapper,
    githubWorkflow,
    readme,
    runbook,
    envExample,
  ].join("\n");

  assertNoMatch(infrastructureText, /(?:\.\.\/web-php-infrastructure|src\/infrastructure|enterprise-infrastructure)/, "Infrastructure must not reference retired duplicate infra directories.");
  assertMatch(compose, /^name:\s+stexor_platform_local/m, "Compose must set a stable local project name.");
  assertMatch(compose, /dockerfile:\s+docker\/php-apache\.Dockerfile/, "Compose must build PHP hosting from the unified infra Dockerfile.");
  assertMatch(compose, /\.\/php-apache\/apache:\/etc\/apache2\/sites-available/, "Compose must mount the unified PHP Apache vhost configs.");
  assertMatch(compose, /\.\/php-apache\/php\/custom\.ini/, "Compose must mount the unified PHP runtime config.");
  assertMatch(compose, /\.\/mariadb\/initdb:/, "Compose must initialize MariaDB from the unified infra tree.");
  assertMatch(compose, /x-default-logging:[\s\S]*max-size:\s+"10m"[\s\S]*max-file:\s+"5"/, "Compose services must define bounded json-file logging.");
  assertMatch(composeBuild, /BACKEND_BUILD_IMAGE[\s\S]*WEB_BUILD_IMAGE[\s\S]*WORKER_NOTIFICATIONS_BUILD_IMAGE[\s\S]*WORKER_JOBS_BUILD_IMAGE/, "Compose build must use local build image variables.");
  assertMatch(composeSecrets, /SESSION_SIGNING_KEYS_FILE:\s+\/run\/secrets\/session_signing_keys/, "Local secret overlay must consume session signing keys from Docker secrets.");
  assertMatch(composeSecrets, /MARIADB_ROOT_PASSWORD_FILE:\s+\/run\/secrets\/mariadb_root_password/, "Local secret overlay must consume MariaDB root password from Docker secrets.");
  assertMatch(composeWaf, /owasp\/modsecurity-crs:4\.26\.0-nginx-202605200705@sha256:[a-f0-9]{64}/, "WAF image must be a pinned OWASP CRS image.");
  assertMatch(composeWaf, /BLOCKING_PARANOIA:\s+\$\{WAF_BLOCKING_PARANOIA:-2\}/, "WAF must default to CRS blocking paranoia level 2.");
  assertMatch(composeWaf, /REQUEST-900-EXCLUSION-RULES-BEFORE-CRS\.conf/, "WAF must load local pre-CRS rules.");
  assertMatch(composeHostingerWaf, /ports:\s*!override[\s\S]*WAF_HTTP_BIND/, "Hostinger WAF overlay must make the WAF the only public HTTP listener.");
  assertMatch(localWafPreRules, /\(\?:traefik\|prometheus\|alertmanager\)\\\.localhost\\\.com/, "Local WAF must block unauthenticated internal console hostnames.");
  assertMatch(hostingerWafPreRules, /\(\?:phpmyadmin\|traefik\|prometheus\|alertmanager\|grafana\|minio\|s3\)/, "Hostinger WAF must block public admin/storage console hostnames.");
  assertNoMatch(compose, /phpmyadmin\/themes\/|blueberry/i, "phpMyAdmin must not mount removed local themes.");
  assertMatch(phpMyAdminConfig, /\$cfg\['ThemeDefault'\]\s*=\s*'pmahomme'/, "phpMyAdmin must use the bundled default pmahomme theme.");
  assertMatch(phpMyAdminConfig, /\$cfg\['ThemeManager'\]\s*=\s*false/, "phpMyAdmin theme switching must be disabled.");
  assertMatch(phpApacheDockerfile, /php:8\.5-apache@sha256:[a-f0-9]{64}/, "PHP Apache image must be pinned to a digest.");
  assertMatch(phpApacheDockerfile, /a2enmod(?=[^\n]*rewrite)(?=[^\n]*headers)(?=[^\n]*ssl)(?=[^\n]*proxy)(?=[^\n]*proxy_http)/, "PHP Apache image must enable the required hosting modules.");
  assertMatch(opsDockerfile, /docker-cli[\s\S]*docker-cli-compose/, "Ops container must include Docker CLI and Compose plugin.");
  assertMatch(opsWrapper, /docker build[\s\S]*docker\/ops\.Dockerfile[\s\S]*docker run --rm/, "Ops wrapper must execute commands through the containerized runner.");
  assertMatch(opsWrapper, /\/var\/run\/docker\.sock/, "Ops wrapper must mount the Docker socket for controlled Docker operations.");
  assertMatch(opsWrapper, /INFRA_CONTAINER_ROOT="\$\{STEXOR_INFRA_CONTAINER_ROOT:-\/infra\}"/, "Ops wrapper must mount infrastructure at /infra to match the ops image entrypoint.");
  assertMatch(opsWrapper, /SOURCE_CONTAINER_ROOT="\$\{STEXOR_SOURCE_CONTAINER_ROOT:-\/src_stexor\}"/, "Ops wrapper must mount source at /src_stexor by default.");
  assertNoMatch(opsWrapper, /INFRA_CONTAINER_ROOT="\$\{STEXOR_INFRA_CONTAINER_ROOT:-\$INFRA_ROOT\}"/, "Ops wrapper must not use the host workspace path as the default container root.");
  assertMatch(backupSchedulerScript, /BACKUP_SCHEDULER_DRY_RUN/, "Backup scheduler must support CI dry-run mode.");
  assertMatch(opsScript, /async function staticSecurityCheck/, "Ops script must expose the full static security gate.");
  assertNoMatch(githubWorkflow, /Stexor-account|STEXOR_APP_REPO_TOKEN|Checkout application source/, "Infrastructure CI must not checkout or require project repositories.");
  assertMatch(githubWorkflow, /\.tmp\/optional-node-source/, "Infrastructure CI must use a local optional source placeholder for Compose rendering.");
  assertMatch(githubWorkflow, /static-security-check --infraOnly/, "Infrastructure CI must run infrastructure-only static checks.");
  assertMatch(githubWorkflow, /Repository coverage audit[\s\S]*repo-coverage-check/, "Infrastructure CI must audit tracked repository file coverage.");
  assertMatch(githubWorkflow, /Render staging and backup compose[\s\S]*compose\.waf\.yaml[\s\S]*compose\.staging\.yaml[\s\S]*compose\.backup-scheduler\.yaml/, "Infrastructure CI must render staging, WAF and backup scheduler compose overlays.");
  assertMatch(githubWorkflow, /Cloudflare from-zero dry run[\s\S]*cloudflare-from-zero --manifest cloudflare\/from-zero\.example\.json/, "Infrastructure CI must exercise the additive-only Cloudflare from-zero plan.");
  assertMatch(githubWorkflow, /GitHub Actions run evidence plan[\s\S]*github-actions-run-evidence/, "Infrastructure CI must generate a GitHub Actions run evidence plan.");
  assertMatch(githubWorkflow, /Secret scan[\s\S]*secret-scan/, "Infrastructure CI must run the secret scanner.");
  assertMatch(githubWorkflow, /HA configuration check[\s\S]*ha-config-check/, "Infrastructure CI must run the HA configuration check.");
  assertMatch(githubWorkflow, /Managed secrets preflight[\s\S]*managed-secrets-preflight/, "Infrastructure CI must run the managed secrets preflight.");
  assertMatch(githubWorkflow, /Secret rotation evidence plan[\s\S]*secret-rotation-evidence/, "Infrastructure CI must write a secret rotation evidence plan.");
  assertMatch(githubWorkflow, /DR readiness check[\s\S]*dr-readiness-check/, "Infrastructure CI must run the DR readiness check.");
  assertMatch(githubWorkflow, /DR evidence summary[\s\S]*dr-evidence/, "Infrastructure CI must write a DR evidence summary.");
  assertMatch(githubWorkflow, /Off-site restore drill plan[\s\S]*offsite-restore-drill-restic --planOnly/, "Infrastructure CI must exercise the off-site restore drill plan.");
  assertMatch(githubWorkflow, /Release artifact gate dry run[\s\S]*release-artifact-gate --envFile \.tmp\/ci-release\.env --sbom \.tmp\/ci-sbom\/pnpm-sbom-ci\.json/, "Infrastructure CI must exercise release image and SBOM admission.");
  assertMatch(githubWorkflow, /DEPLOY_RUN_PRODUCTION_PREFLIGHT:\s+"1"[\s\S]*DEPLOY_RUN_PRE_GO_LIVE:\s+"1"[\s\S]*DEPLOY_RUN_GO_NO_GO:\s+"1"/, "Production deploy workflow must enforce preflight, pre-go-live evidence and go/no-go.");
  assertMatch(githubWorkflow, /DEPLOY_PRE_GO_LIVE_RESTORE_DRILL:\s+"1"[\s\S]*DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN:\s+"1"/, "Production deploy workflow must require restore and off-site restore evidence.");
  assertMatch(githubWorkflow, /Upload CI evidence reports[\s\S]*actions\/upload-artifact@v4[\s\S]*reports\/[\s\S]*\.tmp\/evidence-bundles\/[\s\S]*retention-days:\s+30/, "Infrastructure CI must upload non-secret evidence reports.");
  assertMatch(githubWorkflow, /Evidence bundle integrity verify[\s\S]*evidence-bundle-verify/, "Infrastructure CI must verify evidence bundle manifest integrity.");
  assertMatch(githubWorkflow, /Pre go-live evidence report[\s\S]*pre-go-live-evidence --infraOnly --repo/, "Infrastructure CI must produce an infrastructure-only pre go-live evidence report.");
  assertMatch(githubWorkflow, /Enterprise requirements traceability[\s\S]*enterprise-requirements-check/, "Infrastructure CI must verify enterprise requirements traceability.");
  assertMatch(githubWorkflow, /Production readiness checklist[\s\S]*enterprise-requirements-check --manifest governance\/production-readiness\.json/, "Infrastructure CI must verify the 20-point production readiness checklist.");
  assertMatch(githubWorkflow, /Production live proof gate rejects missing evidence[\s\S]*--requireLiveProofs[\s\S]*Live proof gate passed without real production evidence/, "Infrastructure CI must prove the live-production gate rejects missing external evidence.");
  assertMatch(productionReadinessManifest, /"expectedCount":\s*20/, "Production readiness manifest must track the exact 20-point checklist.");
  assertMatch(productionReadinessManifest, /"liveProofCheckRequired":\s*true/, "Production readiness manifest must require mapped live proof checks.");
  assertMatch(productionReadinessManifest, /"liveProofChecks"/, "Production readiness requirements must map to production go/no-go live checks.");
  assertMatch(githubWorkflow, /permissions:\s*\r?\n\s+contents:\s+read/, "Infrastructure CI must declare least-privilege read permissions.");
  assertNoMatch(githubWorkflow, /security-events:\s+write|contents:\s+write/, "Infrastructure CI must not request unused write permissions.");
  assertMatch(githubWorkflow, /compose-and-policy:[\s\S]*timeout-minutes:\s+45[\s\S]*shell-syntax:[\s\S]*timeout-minutes:\s+10[\s\S]*dast-zap:[\s\S]*timeout-minutes:\s+45[\s\S]*deploy-hostinger:[\s\S]*timeout-minutes:\s+90/, "Infrastructure CI jobs must set explicit timeouts.");
  assertMatch(opsScript, /async function repoCoverageCheck/, "Ops script must provide a repository coverage audit command.");
  assertMatch(opsScript, /"repo-coverage-check": repoCoverageCheck/, "Ops command map must expose repo-coverage-check.");
  assertMatch(opsScript, /repoStatus:[\s\S]*liveProofStatus[\s\S]*liveProofsPending/, "Enterprise requirement reports must separate repository evidence from pending live production proof.");
  assertMatch(evidenceBundleVerifyWrapper, /evidence-bundle-verify/, "Evidence bundle verify wrapper must delegate to the Dockerized ops runner.");
  assertMatch(opsScript, /async function evidenceBundleVerify[\s\S]*sha256 mismatch[\s\S]*required report is not passing[\s\S]*--requireComplete/, "Ops script must verify evidence bundle SHA256, report status and completeness.");
  assertMatch(githubActionsRunEvidenceWrapper, /github-actions-run-evidence/, "GitHub Actions run evidence wrapper must delegate to the Dockerized ops runner.");
  assertMatch(opsScript, /async function githubActionsRunEvidence[\s\S]*workflow_runs[\s\S]*run\.conclusion !== "success"/, "Ops script must verify remote GitHub Actions workflow success.");
  assertMatch(productionGoNoGoPolicyText, /"requireGithubActionsRunSuccess":\s*true[\s\S]*"requiredGithubWorkflow":\s*"enterprise-infra\.yml"/, "Production go/no-go policy must require a successful remote GitHub Actions workflow run.");
  assertMatch(secretRotationEvidenceWrapper, /secret-rotation-evidence/, "Secret rotation evidence wrapper must delegate to the Dockerized ops runner.");
  assertMatch(opsScript, /async function secretRotationEvidence[\s\S]*secret-rotation-evidence-[\s\S]*expiredSecrets/, "Ops script must provide non-secret secret rotation evidence reports.");
  assertMatch(opsScript, /latestJsonReport\("secret-rotation", "secret-rotation-evidence-"/, "Production go/no-go must evaluate secret rotation evidence reports.");
  assertMatch(productionGoNoGoPolicyText, /"requireSecretRotationEvidence":\s*true/, "Production go/no-go policy must require secret rotation evidence.");
  assertMatch(productionGoNoGoPolicyText, /"secretRotation":\s*24/, "Production go/no-go policy must require fresh secret rotation evidence.");
  assertMatch(productionReadinessManifest, /"secrets-management"[\s\S]*"secret-rotation-evidence"/, "Production readiness must map secrets management to the dedicated secret rotation live proof.");
  assertMatch(hostingerPostdeployScript, /secret-rotation-evidence\.sh --enforce[\s\S]*production-go-no-go\.sh --enforce[\s\S]*production-readiness-live\.sh/, "Hostinger post-deploy must enforce secret rotation evidence, production go/no-go and live readiness.");
  assertMatch(productionReadinessLiveWrapper, /enterprise-requirements-check --manifest governance\/production-readiness\.json --requireLiveProofs/, "Production readiness live wrapper must enforce the 20-point live checklist.");
  assertMatch(opsScript, /directory: "production-readiness"[\s\S]*prefix: "production-readiness-"[\s\S]*required: true/, "Evidence bundle must require the live production readiness report.");
  assertMatch(readme, /production-readiness-live\.sh[\s\S]*reports\/production-readiness/, "README must document the live production readiness report.");
  assertMatch(runbook, /production-readiness-live\.sh[\s\S]*reports\/production-readiness/, "Runbook must document the live production readiness report.");
  assertMatch(opsScript, /workerNotificationsServerPath[\s\S]*fs\.existsSync\(workerNotificationsServerPath\)/, "Alert evidence must treat Stexor source checks as optional.");
  assertMatch(githubWorkflow, /Backup scheduler dry run[\s\S]*BACKUP_SCHEDULER_DRY_RUN=true/, "Infrastructure CI must exercise the Dockerized backup scheduler in dry-run mode.");
  assertNoMatch(githubWorkflow, /setup-node|node scripts\/stexor-ops\.mjs|shell:\s+pwsh|\.ps1/, "Infrastructure CI must stay Linux/container-first without PowerShell or host Node policy gates.");
  assertMatch(productionGoNoGoPolicyText, /"vpsHost"[\s\S]*"cloudflareAccess"/, "Production go/no-go policy must require VPS and Cloudflare evidence.");
  assertMatch(infraRenovate, /dependencyDashboardApproval/, "Renovate must require dashboard approval for controlled updates.");
  assertMatch(infraGitattributes, /^\* text=auto eol=lf/m, "Infrastructure repo must enforce LF line endings.");
  assertMatch(gitignore, /^\.tmp\/$/m, "Generated ops temp files must be ignored by Git.");

  log("Infra-only static security checks passed.");
}

async function staticSecurityCheck() {
  if (booleanFlag(argv.infraOnly) || booleanFlag(process.env.STEXOR_STATIC_INFRA_ONLY)) {
    staticSecurityInfraOnlyCheck();
    return;
  }
  log("==> Static security checks");
  const compose = readText(path.join(infraRoot, "compose.yaml"));
  const composeBuild = readText(path.join(infraRoot, "compose.build.yaml"));
  const composeProd = readText(path.join(infraRoot, "compose.prod.yaml"));
  const composeSecrets = readText(path.join(infraRoot, "compose.secrets.yaml"));
  const composeWaf = readText(path.join(infraRoot, "compose.waf.yaml"));
  const composeBackupScheduler = readText(path.join(infraRoot, "compose.backup-scheduler.yaml"));
  const composeHostingerWaf = readText(path.join(infraRoot, "compose.hostinger-waf.yaml"));
  const composeStaging = readText(path.join(infraRoot, "compose.staging.yaml"));
  const composeHa = readText(path.join(infraRoot, "compose.ha.yaml"));
  const composeManagedSecrets = readText(path.join(infraRoot, "compose.managed-secrets.yaml"));
  const composeDr = readText(path.join(infraRoot, "compose.dr.yaml"));
  const traefikConfig = readText(path.join(infraRoot, "traefik", "traefik.yml"));
  const localProjectsPagePath = path.resolve(infraRoot, "..", "src", "public", "index.php");
  const localProjectsPage = fs.existsSync(localProjectsPagePath) ? readText(localProjectsPagePath) : "";
  const prometheusConfig = readText(path.join(infraRoot, "prometheus", "prometheus.yml"));
  const localWafPreRules = readText(path.join(infraRoot, "waf", "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"));
  const hostingerWafPreRules = readText(path.join(infraRoot, "waf", "REQUEST-900-HOSTINGER-RULES-BEFORE-CRS.conf"));
  const phpMyAdminConfig = readText(path.join(infraRoot, "phpmyadmin", "config.user.inc.php"));
  const prometheusAlerts = readText(path.join(infraRoot, "prometheus", "rules", "enterprise-alerts.yml"));
  const alertmanagerConfig = readText(path.join(infraRoot, "alertmanager", "alertmanager.yml"));
  const lokiConfig = readText(path.join(infraRoot, "loki", "config.yml"));
  const lokiWafAlerts = readText(path.join(infraRoot, "loki", "rules", "stexor", "waf-alerts.yml"));
  const promtailConfig = readText(path.join(infraRoot, "promtail", "config.yml"));
  const grafanaOverviewDashboard = readText(path.join(infraRoot, "grafana", "dashboards", "enterprise-overview.json"));
  const backendDockerfile = readText(path.join(infraRoot, "docker", "backend.Dockerfile"));
  const webDockerfile = readText(path.join(infraRoot, "docker", "web.Dockerfile"));
  const workerDockerfile = readText(path.join(infraRoot, "docker", "worker.Dockerfile"));
  const opsDockerfile = readText(path.join(infraRoot, "docker", "ops.Dockerfile"));
  const opsWrapper = readText(path.join(infraRoot, "scripts", "stexor-ops.sh"));
  const backupSchedulerScript = readText(path.join(infraRoot, "scripts", "backup-scheduler.sh"));
  const opsScript = readText(path.join(infraRoot, "scripts", "stexor-ops.mjs"));
  const secretManagerScript = readText(path.join(infraRoot, "scripts", "stexor-secret-manager.mjs"));
  const backendConfig = readText(path.join(sourceRoot, "apps", "backend", "src", "server-config.ts"));
  const backendRedisStore = readText(path.join(sourceRoot, "apps", "backend", "src", "runtime", "redis-store.ts"));
  const backendSessionAuth = readText(path.join(sourceRoot, "apps", "backend", "src", "runtime", "session-auth.ts"));
  const observabilitySource = readText(path.join(sourceRoot, "packages", "observability", "src", "index.ts"));
  const workerJobsServer = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "server.ts"));
  const workerNotificationsServer = readText(path.join(sourceRoot, "apps", "worker-notifications", "src", "server.ts"));
  const workerJobsAuditOutbox = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "audit-outbox.ts"));
  const workerJobsAuditOutboxStore = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "audit-outbox-store.ts"));
  const workerJobsNatsSink = readText(path.join(sourceRoot, "apps", "worker-jobs", "src", "nats-audit-sink.ts"));
  const sourcePackage = readText(path.join(sourceRoot, "package.json"));
  const sourceInfraOpsLauncher = readText(path.join(sourceRoot, "scripts", "run-infra-ops.mjs"));
  const sourceSupplyChainGate = readText(path.join(sourceRoot, "scripts", "supply-chain-gate.mjs"));
  const sourceCiWorkflow = readText(path.join(sourceRoot, ".github", "workflows", "enterprise-ci.yml"));
  const cryptoRuntime = readText(path.join(sourceRoot, "apps", "backend", "src", "runtime", "crypto.ts"));
  const webNextConfig = readText(path.join(sourceRoot, "apps", "web", "next.config.mjs"));
  const webProxy = readText(path.join(sourceRoot, "apps", "web", "src", "proxy.ts"));
  const webAppNotFound = readText(path.join(sourceRoot, "apps", "web", "src", "app", "not-found.tsx"));
  const webGlobalError = readText(path.join(sourceRoot, "apps", "web", "src", "app", "global-error.tsx"));
  const webRememberModel = readText(path.join(sourceRoot, "apps", "web", "src", "components", "account-center", "model.ts"));
  const e2eStackHelper = readText(path.join(sourceRoot, "e2e", "helpers", "stack.ts"));
  const webSource = readSourceTreeText(path.join(sourceRoot, "apps", "web", "src"));
  const uiSource = readSourceTreeText(path.join(sourceRoot, "packages", "ui", "src"));
  const sourceDocs = readSourceTreeText(path.join(sourceRoot, "docs"), new Set([".md"]));
  const sourceTopLevelDocs = [
    path.join(sourceRoot, "README.md"),
    path.join(sourceRoot, "packages", "ui", "docs", "release-governance.md"),
  ].filter((filePath) => fs.existsSync(filePath)).map((filePath) => readText(filePath)).join("\n");
  const browserUiSource = `${webSource}\n${uiSource}`;
  const enterprisePlan = readText(path.join(infraRoot, "ENTERPRISE-10-PLAN.md"));
  const readme = readText(path.join(infraRoot, "README.md"));
  const runbook = readText(path.join(infraRoot, "RUNBOOK.md"));
  const envExample = readText(path.join(infraRoot, ".env.example"));
  const admissionPolicy = readText(path.join(infraRoot, "security", "admission", "cosign-digest-policy.rego"));
  const branchProtection = readText(path.join(infraRoot, "governance", "github-branch-protection.json"));
  const githubEnvironmentsPolicyText = readText(path.join(infraRoot, "governance", "github-environments.json"));
  const githubEnvironmentsPolicyJson = JSON.parse(githubEnvironmentsPolicyText);
  const githubActionsRuntimePolicyText = readText(path.join(infraRoot, "governance", "github-actions-runtime.json"));
  const githubActionsRuntimePolicyJson = JSON.parse(githubActionsRuntimePolicyText);
  const productionGoNoGoPolicyText = readText(path.join(infraRoot, "governance", "production-go-no-go.json"));
  const productionGoNoGoPolicyJson = JSON.parse(productionGoNoGoPolicyText);
  const productionReadinessManifest = readText(path.join(infraRoot, "governance", "production-readiness.json"));
  const githubWorkflow = readText(path.join(infraRoot, ".github", "workflows", "enterprise-infra.yml"));
  const externalUptimeManifest = readText(path.join(infraRoot, "monitoring", "external-uptime.example.json"));
  const cloudflareReadme = readText(path.join(infraRoot, "cloudflare", "README.md"));
  const cloudflareFromZeroManifest = readText(path.join(infraRoot, "cloudflare", "from-zero.example.json"));
  const cloudflareWafRules = readText(path.join(infraRoot, "cloudflare", "stexor-zone-waf-rules.json"));
  const cloudflareSettings = readText(path.join(infraRoot, "cloudflare", "zone-settings.json"));
  const cloudflareFromZeroScript = readText(path.join(infraRoot, "scripts", "cloudflare-from-zero.mjs"));
  const cloudflareAccessManifest = readText(path.join(infraRoot, "cloudflare", "access-admin.example.json"));
  const cloudflareAccessScript = readText(path.join(infraRoot, "scripts", "cloudflare-access-admin.mjs"));
  const deployHostingerScript = readText(path.join(infraRoot, "scripts", "deploy-hostinger.sh"));
  const hostingerGoLiveScript = readText(path.join(infraRoot, "scripts", "hostinger-go-live.sh"));
  const hostingerPreflightScript = readText(path.join(infraRoot, "scripts", "hostinger-preflight.sh"));
  const hostingerPostdeployScript = readText(path.join(infraRoot, "scripts", "hostinger-postdeploy.sh"));
  const vpsBootstrapScript = readText(path.join(infraRoot, "scripts", "vps-bootstrap-ubuntu.sh"));
  const vpsHardeningScript = readText(path.join(infraRoot, "scripts", "vps-hardening-ubuntu.sh"));
  const vpsHostReadinessScript = readText(path.join(infraRoot, "scripts", "vps-host-readiness.sh"));
  const originLockScript = readText(path.join(infraRoot, "scripts", "cloudflare-origin-lock-ufw.sh"));
  const vpsPredeployChecklist = readText(path.join(infraRoot, "VPS-PREDEPLOY-CHECKLIST.md"));
  const readinessReport = readText(path.join(infraRoot, "READINESS-REPORT.md"));
  const finalReadinessAudit = readText(path.join(infraRoot, "FINAL-READINESS-AUDIT.md"));
  const offsiteCronScript = readText(path.join(infraRoot, "scripts", "install-offsite-backup-cron.sh"));
  const offsiteRestoreDrillWrapper = readText(path.join(infraRoot, "scripts", "offsite-restore-drill-restic.sh"));
  const backupMinioWrapper = readText(path.join(infraRoot, "scripts", "backup-minio.sh"));
  const backupKeycloakWrapper = readText(path.join(infraRoot, "scripts", "backup-keycloak.sh"));
  const backupSecretManagerWrapper = readText(path.join(infraRoot, "scripts", "backup-secret-manager-metadata.sh"));
  const alertEvidenceWrapper = readText(path.join(infraRoot, "scripts", "alert-evidence.sh"));
  const evidenceBundleWrapper = readText(path.join(infraRoot, "scripts", "evidence-bundle.sh"));
  const evidenceBundleVerifyWrapper = readText(path.join(infraRoot, "scripts", "evidence-bundle-verify.sh"));
  const infraHealthWrapper = readText(path.join(infraRoot, "scripts", "infra-health.sh"));
  const failureTestsWrapper = readText(path.join(infraRoot, "scripts", "failure-tests.sh"));
  const drEvidenceWrapper = readText(path.join(infraRoot, "scripts", "dr-evidence.sh"));
  const fullRestoreDrillWrapper = readText(path.join(infraRoot, "scripts", "full-restore-drill.sh"));
  const loadBenchmarkWrapper = readText(path.join(infraRoot, "scripts", "load-benchmark.sh"));
  const linuxPortabilityWrapper = readText(path.join(infraRoot, "scripts", "linux-portability-check.sh"));
  const rollbackReleaseWrapper = readText(path.join(infraRoot, "scripts", "rollback-release.sh"));
  const releaseEvidenceWrapper = readText(path.join(infraRoot, "scripts", "release-evidence.sh"));
  const releaseArtifactGateWrapper = readText(path.join(infraRoot, "scripts", "release-artifact-gate.sh"));
  const externalUptimeWrapper = readText(path.join(infraRoot, "scripts", "external-uptime-check.sh"));
  const cloudflareAccessWrapper = readText(path.join(infraRoot, "scripts", "cloudflare-access-admin.sh"));
  const githubBranchProtectionWrapper = readText(path.join(infraRoot, "scripts", "github-branch-protection.sh"));
  const githubEnvironmentsWrapper = readText(path.join(infraRoot, "scripts", "github-environments.sh"));
  const githubActionsConfigWrapper = readText(path.join(infraRoot, "scripts", "github-actions-config.sh"));
  const githubActionsRunEvidenceWrapper = readText(path.join(infraRoot, "scripts", "github-actions-run-evidence.sh"));
  const secretRotationEvidenceWrapper = readText(path.join(infraRoot, "scripts", "secret-rotation-evidence.sh"));
  const preGoLiveEvidenceWrapper = readText(path.join(infraRoot, "scripts", "pre-go-live-evidence.sh"));
  const productionGoNoGoWrapper = readText(path.join(infraRoot, "scripts", "production-go-no-go.sh"));
  const productionReadinessLiveWrapper = readText(path.join(infraRoot, "scripts", "production-readiness-live.sh"));
  const infraRenovate = readText(path.join(infraRoot, "renovate.json"));
  const sourceRenovate = readText(path.join(sourceRoot, "renovate.json"));
  const infraGitattributes = readText(path.join(infraRoot, ".gitattributes"));
  const sourceGitattributes = readText(path.join(sourceRoot, ".gitattributes"));
  const gitignore = readText(path.join(infraRoot, ".gitignore"));
  const cloudflareFromZero = JSON.parse(cloudflareFromZeroManifest);
  const cloudflareAccess = JSON.parse(cloudflareAccessManifest);

  for (const text of [compose, backendDockerfile, webDockerfile, workerDockerfile, opsDockerfile]) {
    assertMatch(text, /@sha256:[a-f0-9]{64}/, "Base/runtime images must be digest-pinned.");
  }
  assertMatch(opsDockerfile, /^# syntax=docker\/dockerfile:1\.7/m, "Ops Dockerfile must opt into BuildKit syntax.");
  assertMatch(opsDockerfile, /docker-cli[\s\S]*docker-cli-compose/, "Ops container must include Docker CLI and Compose plugin for VPS-only execution.");
  assertMatch(opsDockerfile, /dcron/, "Ops container must include cron for containerized backup scheduling.");
  assertMatch(opsDockerfile, /ENTRYPOINT \["tini", "--", "node", "\/infra\/scripts\/stexor-ops\.mjs"\]/, "Ops container must run the shared operational runner.");
  assertMatch(opsWrapper, /STEXOR_OPS_IMAGE:-stexor\/ops:local/, "Ops wrapper must build and reuse the local ops image.");
  assertMatch(opsWrapper, /docker build[\s\S]*docker\/ops\.Dockerfile[\s\S]*docker run --rm/, "Ops wrapper must execute commands through the containerized runner.");
  assertMatch(opsWrapper, /\/var\/run\/docker\.sock/, "Ops wrapper must mount the Docker socket for controlled Docker operations.");
  assertMatch(opsWrapper, /--network host/, "Ops wrapper must use host networking on Linux so runtime health checks reach local routed domains.");
  assertMatch(opsWrapper, /INFRA_CONTAINER_ROOT="\$\{STEXOR_INFRA_CONTAINER_ROOT:-\/infra\}"/, "Ops wrapper must mount infrastructure at /infra to match the ops image entrypoint.");
  assertMatch(opsWrapper, /SOURCE_CONTAINER_ROOT="\$\{STEXOR_SOURCE_CONTAINER_ROOT:-\/src_stexor\}"/, "Ops wrapper must mount source at /src_stexor by default.");
  assertNoMatch(opsWrapper, /INFRA_CONTAINER_ROOT="\$\{STEXOR_INFRA_CONTAINER_ROOT:-\$INFRA_ROOT\}"/, "Ops wrapper must not use the host workspace path as the default container root.");
  assertMatch(opsWrapper, /Linux\)[\s\S]*LOCAL_HOST_TARGET="\$\{STEXOR_LOCAL_HOST_TARGET:-127\.0\.0\.1\}"/, "Ops wrapper must pin local development domains to loopback on Linux host networking.");
  assertMatch(opsWrapper, /\*\)[\s\S]*LOCAL_HOST_TARGET="\$\{STEXOR_LOCAL_HOST_TARGET:-host-gateway\}"/, "Ops wrapper must route local development domains to the Docker host gateway on Docker Desktop.");
  assertMatch(opsWrapper, /api\.localhost\.com[\s\S]*account\.localhost\.com[\s\S]*--add-host \$host:\$LOCAL_HOST_TARGET/, "Ops wrapper must pin local development domains through the selected local host target.");
  assertMatch(opsWrapper, /STEXOR_INFRA_CONTAINER_ROOT/, "Ops wrapper must pass the infrastructure container root.");
  assertMatch(opsWrapper, /STEXOR_INFRA_VOLUME_SOURCE/, "Ops wrapper must allow overriding the infrastructure host volume source.");
  assertMatch(opsWrapper, /STEXOR_INFRA_HOST_ROOT/, "Ops wrapper must pass the infrastructure host root for nested Docker volume mounts.");
  assertMatch(opsWrapper, /STEXOR_SOURCE_CONTAINER_ROOT/, "Ops wrapper must pass the source container root.");
  assertMatch(opsWrapper, /STEXOR_SOURCE_VOLUME_SOURCE/, "Ops wrapper must allow overriding the source host volume source.");
  assertMatch(opsWrapper, /STEXOR_SOURCE_HOST_ROOT/, "Ops wrapper must pass the source host root for nested Docker volume mounts.");
  const shellWrappers = fs.readdirSync(path.join(infraRoot, "scripts"))
    .filter((name) => name.endsWith(".sh"))
    .map((name) => [name, readText(path.join(infraRoot, "scripts", name))]);
  for (const [name, text] of shellWrappers) {
    if (name === "stexor-ops.sh" || name === "backup-scheduler.sh" || name === "vps-bootstrap-ubuntu.sh" || name === "vps-hardening-ubuntu.sh" || name === "vps-host-readiness.sh" || name === "cloudflare-origin-lock-ufw.sh") {
      continue;
    }
    assertNoMatch(text, /exec node|stexor-ops\.mjs|stexor-secret-manager\.mjs|cloudflare-from-zero\.mjs/, `Shell wrapper ${name} must delegate through the Dockerized ops runner, not host Node.`);
  }
  assertMatch(gitignore, /^\.tmp\/$/m, "Generated ops temp files must be ignored by Git.");
  assertMatch(gitignore, /^release\/$/m, "Generated release manifests and rollback targets must be ignored by Git.");
  assertMatch(gitignore, /^reports\/$/m, "Generated operational reports must be ignored by Git.");
  if (productionGoNoGoPolicyJson.version !== 1) {
    fail("Production go/no-go policy must use version 1.");
  }
  for (const users of [50, 100, 500]) {
    if (!productionGoNoGoPolicyJson.requiredLoadProfiles?.includes(users)) {
      fail(`Production go/no-go policy must require the ${users}-user load profile.`);
    }
  }
  for (const key of [
    "requirePublicLoadTarget",
    "requireLoadEdgeEvidence",
    "requireEmailAlertDelivery",
    "requireOffsiteRestore",
    "requireReleaseProvenance",
    "requireCloudflareAccessVerify",
    "requireSecretRotationEvidence",
    "requireRuntimePreGoLive",
    "requireRestorePreGoLive",
    "requireGithubRemoteVerification",
    "requireProductionPreflight",
  ]) {
    if (productionGoNoGoPolicyJson[key] !== true) {
      fail(`Production go/no-go policy must enable ${key}.`);
    }
  }
  assertMatch(productionGoNoGoPolicyText, /"maxAgeHours"[\s\S]*"vpsHost"[\s\S]*"cloudflareAccess"[\s\S]*"secretRotation"/, "Production go/no-go policy must define evidence freshness budgets.");
  assertMatch(composeBackupScheduler, /backup-scheduler:[\s\S]*profiles:\s*\r?\n\s+- backup/, "Backup scheduler must be an opt-in Compose profile.");
  assertMatch(composeBackupScheduler, /logging:[\s\S]*max-size:\s+"10m"[\s\S]*max-file:\s+"5"/, "Backup scheduler must use bounded container logging.");
  assertMatch(composeBackupScheduler, /image:\s+\$\{STEXOR_OPS_IMAGE:-stexor\/ops:local\}/, "Backup scheduler must reuse the Dockerized ops image.");
  assertMatch(composeBackupScheduler, /docker\/ops\.Dockerfile/, "Backup scheduler must be buildable from the ops Dockerfile.");
  assertMatch(composeBackupScheduler, /\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/, "Backup scheduler must use Docker from inside the ops container.");
  assertMatch(composeBackupScheduler, /backup-scheduler\.sh/, "Backup scheduler service must run the container-local scheduler script.");
  assertMatch(composeBackupScheduler, /BACKUP_SCHEDULER_ENABLE_OFFSITE/, "Backup scheduler must support opt-in off-site backup upload.");
  assertMatch(composeBackupScheduler, /STEXOR_INFRA_HOST_ROOT:\s+\$\{STEXOR_INFRA_HOST_ROOT:-\}/, "Backup scheduler must not hardcode a VPS host path by default.");
  assertMatch(composeBackupScheduler, /STEXOR_SOURCE_HOST_ROOT:\s+\$\{STEXOR_SOURCE_HOST_ROOT:-\}/, "Backup scheduler must not hardcode a source host path by default.");
  assertMatch(backupSchedulerScript, /detect_mount_source[\s\S]*docker inspect "\$container_id"/, "Backup scheduler must autodetect host mount sources from Docker.");
  assertMatch(backupSchedulerScript, /BACKUP_SCHEDULER_ENV_FILE[\s\S]*write_env_var STEXOR_INFRA_HOST_ROOT/, "Backup scheduler must pass detected host roots through a private runtime env file.");
  assertMatch(backupSchedulerScript, /load_runtime_env\(\)[\s\S]*export "\$name=\$value"[\s\S]*--run/, "Backup scheduler must parse its private runtime env file without sourcing it.");
  assertNoMatch(backupSchedulerScript, /(^|\n)\s*\.\s+"\$ENV_FILE"|printf '\. %s &&/, "Backup scheduler must not source its runtime env file.");
  assertMatch(backupSchedulerScript, /backup-postgres[\s\S]*backup-mariadb[\s\S]*backup-minio[\s\S]*backup-keycloak[\s\S]*backup-secret-manager-metadata/, "Backup scheduler must schedule all local backup families.");
  assertMatch(backupSchedulerScript, /full-restore-drill/, "Backup scheduler must schedule a regular full restore drill.");
  assertMatch(backupSchedulerScript, /prune-postgres-backups/, "Backup scheduler must schedule retention cleanup.");
  assertMatch(backupSchedulerScript, /offsite-backup-restic/, "Backup scheduler must support off-site Restic upload.");
  assertMatch(backupSchedulerScript, /crond -f/, "Backup scheduler must run cron in the foreground inside the container.");
  assertMatch(compose, /x-default-logging:[\s\S]*max-size:\s+"10m"[\s\S]*max-file:\s+"5"/, "Compose services must define bounded json-file logging.");
  assertMatch(compose, /^name:\s+stexor_platform_local/m, "Compose must set a stable local project name to avoid accidental duplicate stacks.");
  assertMatch(composeBuild, /BACKEND_BUILD_IMAGE[\s\S]*WEB_BUILD_IMAGE[\s\S]*WORKER_NOTIFICATIONS_BUILD_IMAGE[\s\S]*WORKER_JOBS_BUILD_IMAGE/, "Compose build must use local build image variables.");
  assertMatch(composeBuild, /cache_from:[\s\S]*cache_to:/, "Compose build must define reusable BuildKit cache import/export.");
  assertMatch(composeBuild, /NEXT_PUBLIC_API_URL[\s\S]*NEXT_PUBLIC_ACCOUNT_URL/, "Compose build must pass public web URLs into the Next.js production build.");
  assertNoMatch(composeBuild, /\$\{(?:BACKEND_IMAGE|WEB_IMAGE|WORKER_NOTIFICATIONS_IMAGE|WORKER_JOBS_IMAGE)[:-]/, "Compose build must not reuse production release image variables.");
  assertNoMatch(traefikConfig, /insecure:\s+true/, "Traefik API/dashboard must not be exposed in insecure mode.");
  assertNoMatch(traefikConfig, /dashboard:\s+true/, "Traefik dashboard must be disabled unless protected by an explicit auth gateway.");
  assertNoMatch(compose, /8090:8080|api@internal|traefik\.localhost\.com/, "Traefik dashboard must not be routed or exposed in the local stack.");
  assertNoMatch(compose, /prometheus\.localhost\.com|alertmanager\.localhost\.com/, "Prometheus and Alertmanager must remain internal; use authenticated Grafana for browser access.");
  if (localProjectsPage) {
    assertNoMatch(localProjectsPage, /prometheus\.localhost\.com|alertmanager\.localhost\.com|traefik\.localhost\.com/, "Projects page must not link unauthenticated internal consoles.");
  }
  assertMatch(composeHa, /failure_action:\s+rollback/, "HA overlay must rollback failed rolling updates.");
  assertMatch(composeHa, /max_replicas_per_node:\s+1/, "HA overlay must spread stateless replicas across nodes.");
  assertMatch(composeManagedSecrets, /SESSION_SECRET_FILE:\s+\/run\/secrets\/session_secret/, "Managed secret overlay must consume session secret through a file.");
  assertMatch(composeManagedSecrets, /SESSION_SIGNING_KEYS_FILE:\s+\/run\/secrets\/session_signing_keys/, "Managed secret overlay must consume session signing keys through a file.");
  assertMatch(composeManagedSecrets, /PROJECTS_GATEWAY_SIGNING_KEYS_FILE:\s+\/run\/secrets\/projects_gateway_signing_keys/, "Managed secret overlay must consume projects gateway signing keys through a file.");
  assertMatch(composeManagedSecrets, /GOOGLE_RECAPTCHA_SECRET_KEY_FILE:\s+\/run\/secrets\/google_recaptcha_secret_key/, "Managed secret overlay must consume Google reCAPTCHA secret through a file.");
  assertMatch(composeManagedSecrets, /CLOUDFLARE_TURNSTILE_SECRET_KEY_FILE:\s+\/run\/secrets\/cloudflare_turnstile_secret_key/, "Managed secret overlay must consume Cloudflare Turnstile secret through a file.");
  assertMatch(composeManagedSecrets, /GOOGLE_OAUTH_CLIENT_SECRET_FILE:\s+\/run\/secrets\/google_oauth_client_secret/, "Managed secret overlay must consume Google OAuth client secret through a file.");
  assertMatch(composeManagedSecrets, /ALERTMANAGER_WEBHOOK_TOKEN_FILE:\s+\/run\/secrets\/alertmanager_webhook_token/, "Managed secret overlay must consume the Alertmanager webhook token through a file.");
  assertMatch(composeManagedSecrets, /MARIADB_ROOT_PASSWORD_FILE:\s+\/run\/secrets\/mariadb_root_password/, "Managed secret overlay must consume MariaDB root password through a Docker secret file.");
  assertMatch(composeManagedSecrets, /^ {2}mariadb_root_password:\s*\r?\n {4}external:\s+true/m, "Managed secret overlay must declare MariaDB root password as an external Docker secret.");
  assertMatch(composeManagedSecrets, /PMA_CONTROL_PASSWORD_FILE:\s+\/run\/secrets\/phpmyadmin_control_password/, "Managed secret overlay must consume phpMyAdmin control password through a Docker secret file.");
  assertMatch(composeManagedSecrets, /^ {2}phpmyadmin_control_password:\s*\r?\n {4}external:\s+true/m, "Managed secret overlay must declare phpMyAdmin control password as an external Docker secret.");
  assertMatch(composeManagedSecrets, /external:\s+true/, "Managed secret overlay must use external Docker secrets.");
  assertMatch(composeSecrets, /SESSION_SIGNING_KEYS_FILE:\s+\/run\/secrets\/session_signing_keys/, "Local secret overlay must consume session signing keys through a Docker secret file.");
  assertMatch(composeSecrets, /PROJECTS_GATEWAY_SIGNING_KEYS_FILE:\s+\/run\/secrets\/projects_gateway_signing_keys/, "Local secret overlay must consume projects gateway signing keys through a Docker secret file.");
  assertMatch(composeSecrets, /GOOGLE_RECAPTCHA_SECRET_KEY_FILE:\s+\/run\/secrets\/google_recaptcha_secret_key/, "Local secret overlay must consume Google reCAPTCHA secret through a Docker secret file.");
  assertMatch(composeSecrets, /CLOUDFLARE_TURNSTILE_SECRET_KEY_FILE:\s+\/run\/secrets\/cloudflare_turnstile_secret_key/, "Local secret overlay must consume Cloudflare Turnstile secret through a Docker secret file.");
  assertMatch(composeSecrets, /GOOGLE_OAUTH_CLIENT_SECRET_FILE:\s+\/run\/secrets\/google_oauth_client_secret/, "Local secret overlay must consume Google OAuth client secret through a Docker secret file.");
  assertMatch(composeSecrets, /ALERTMANAGER_WEBHOOK_TOKEN_FILE:\s+\/run\/secrets\/alertmanager_webhook_token/, "Local secret overlay must consume the Alertmanager webhook token through a Docker secret file.");
  assertMatch(compose, /ALERT_DISCORD_WEBHOOK_URL_FILE:\s+\$\{ALERT_DISCORD_WEBHOOK_URL_FILE:-\}/, "Compose must expose optional Discord alert webhook secret-file configuration.");
  assertMatch(compose, /ALERT_TELEGRAM_BOT_TOKEN_FILE:\s+\$\{ALERT_TELEGRAM_BOT_TOKEN_FILE:-\}/, "Compose must expose optional Telegram alert bot token secret-file configuration.");
  assertMatch(compose, /ALERT_TELEGRAM_CHAT_ID:\s+\$\{ALERT_TELEGRAM_CHAT_ID:-\}/, "Compose must expose optional Telegram alert chat id configuration.");
  assertMatch(composeWaf, /owasp\/modsecurity-crs:4\.26\.0-nginx-202605200705@sha256:[a-f0-9]{64}/, "WAF image must be an explicit stable CRS tag pinned by digest.");
  assertMatch(composeWaf, /traefik:[\s\S]*ports:\s*!override \[\]/, "WAF overlay must keep Traefik off host ports.");
  assertMatch(composeWaf, /container_name:\s+enterprise-waf[\s\S]*security_opt:\s*\r?\n\s+- no-new-privileges:true/, "WAF container must run with no-new-privileges.");
  assertMatch(composeWaf, /BLOCKING_PARANOIA:\s+\$\{WAF_BLOCKING_PARANOIA:-2\}/, "WAF must default to CRS blocking paranoia level 2.");
  assertMatch(composeWaf, /DETECTION_PARANOIA:\s+\$\{WAF_DETECTION_PARANOIA:-2\}/, "WAF must default to CRS detection paranoia level 2.");
  assertMatch(composeWaf, /MODSEC_AUDIT_ENGINE:\s+\$\{WAF_MODSEC_AUDIT_ENGINE:-RelevantOnly\}/, "WAF audit logging must default to relevant events only.");
  assertMatch(composeWaf, /MODSEC_RESP_BODY_ACCESS:\s+\$\{WAF_MODSEC_RESP_BODY_ACCESS:-Off\}/, "WAF must not inspect or log response bodies by default.");
  assertMatch(composeWaf, /REQUEST-900-EXCLUSION-RULES-BEFORE-CRS\.conf/, "WAF must load pre-CRS local rules.");
  assertMatch(composeWaf, /RESPONSE-999-EXCLUSION-RULES-AFTER-CRS\.conf/, "WAF must load post-CRS local tuning rules.");
  assertMatch(localWafPreRules, /ruleRemoveTargetById=942120;ARGS:aPath[\s\S]*ruleRemoveTargetById=942120;ARGS:vPath/, "Local WAF must allow phpMyAdmin navigation base64 paths without disabling CRS globally.");
  assertMatch(localWafPreRules, /\(\?:traefik\|prometheus\|alertmanager\)\\\.localhost\\\.com/, "Local WAF must block unauthenticated internal console hostnames.");
  assertMatch(hostingerWafPreRules, /\(\?:phpmyadmin\|traefik\|prometheus\|alertmanager\|grafana\|minio\|s3\)/, "Hostinger WAF must block public admin/storage console hostnames.");
  assertNoMatch(compose, /phpmyadmin\/themes\//, "phpMyAdmin must use bundled image themes without local theme mounts.");
  assertMatch(phpMyAdminConfig, /\$cfg\['ThemeDefault'\]\s*=\s*'pmahomme'/, "phpMyAdmin must use the bundled default pmahomme theme.");
  assertMatch(phpMyAdminConfig, /\$cfg\['ThemeManager'\]\s*=\s*false/, "phpMyAdmin theme switching must be disabled so stale browser theme cookies cannot select removed local themes.");
  assertNoMatch(compose, /blueberry/i, "phpMyAdmin must not mount the removed Blueberry theme.");
  assertMatch(composeHostingerWaf, /ports:\s*!override[\s\S]*WAF_HTTP_BIND/, "Hostinger WAF overlay must make the WAF the only public HTTP listener.");
  assertMatch(composeHostingerWaf, /BACKEND:\s+\$\{WAF_BACKEND:-http:\/\/traefik:80\}/, "Hostinger WAF overlay must forward to internal HTTP Traefik.");
  assertMatch(opsScript, /async function wafSmoke/, "Ops script must provide a WAF smoke gate.");
  assertMatch(opsScript, /XSS probe/, "WAF smoke gate must test XSS blocking.");
  assertMatch(composeStaging, /container_name:\s*!reset null/, "Staging overlay must remove fixed container names.");
  assertMatch(composeStaging, /enterprise_postgres_data_staging/, "Staging overlay must use separate data volumes.");
  assertMatch(githubWorkflow, /name:\s+enterprise-infra/, "GitHub Actions must define an enterprise infra workflow.");
  assertMatch(githubWorkflow, /dast-zap/, "GitHub Actions must include an opt-in DAST job.");
  assertMatch(githubWorkflow, /deploy-hostinger/, "GitHub Actions must include a controlled Hostinger deploy job.");
  assertMatch(githubWorkflow, /projects_gateway_signing_keys/, "GitHub Actions compose render must provide the Projects gateway signing secret placeholder.");
  assertMatch(githubWorkflow, /Backup scheduler dry run[\s\S]*BACKUP_SCHEDULER_DRY_RUN=true/, "Infrastructure CI must exercise the Dockerized backup scheduler in dry-run mode.");
  assertMatch(githubWorkflow, /External uptime manifest dry run[\s\S]*external-uptime-check --dryRun/, "Infrastructure CI must validate the external uptime manifest.");
  assertMatch(githubWorkflow, /Cloudflare from-zero dry run[\s\S]*cloudflare-from-zero --manifest cloudflare\/from-zero\.example\.json/, "Infrastructure CI must validate the additive-only Cloudflare bootstrap manifest.");
  assertMatch(githubWorkflow, /GitHub branch protection dry run[\s\S]*github-branch-protection --repo/, "Infrastructure CI must validate the GitHub branch protection policy command.");
  assertMatch(githubWorkflow, /Evidence bundle smoke[\s\S]*evidence-bundle --noArchive/, "Infrastructure CI must smoke-test the evidence bundle command.");
  assertMatch(githubWorkflow, /Evidence bundle integrity verify[\s\S]*evidence-bundle-verify/, "Infrastructure CI must verify evidence bundle manifest integrity.");
  assertMatch(githubWorkflow, /sh \.\/scripts\/stexor-ops\.sh static-security-check/, "Infrastructure CI must run the Dockerized ops wrapper instead of host Node.");
  assertNoMatch(githubWorkflow, /setup-node|node scripts\/stexor-ops\.mjs|shell:\s+pwsh|\.ps1/, "Infrastructure CI must stay Linux/container-first without PowerShell or host Node policy gates.");
  assertMatch(deployHostingerScript, /ssh "\$REMOTE" sh -s --[\s\S]*<<'REMOTE_SCRIPT'[\s\S]*remote_dir="\$1"[\s\S]*cd "\$remote_dir"/, "Hostinger deploy must pass remote values through SSH positional arguments instead of interpolating a remote shell string.");
  assertNoMatch(deployHostingerScript, /ssh "\$REMOTE" "set -eu/, "Hostinger deploy must not interpolate the remote deployment script into one shell string.");
  assertMatch(deployHostingerScript, /DEPLOY_RUN_PRE_GO_LIVE[\s\S]*DEPLOY_RUN_GO_NO_GO[\s\S]*hostinger-postdeploy\.sh/, "Hostinger deploy script must run post-deploy health and optional evidence gates.");
  assertMatch(hostingerPreflightScript, /compose\.hostinger\.yaml[\s\S]*compose\.waf\.yaml[\s\S]*compose\.hostinger-waf\.yaml[\s\S]*config --quiet[\s\S]*compose\.hostinger\.yaml[\s\S]*compose\.waf\.yaml[\s\S]*compose\.hostinger-waf\.yaml[\s\S]*grep -E 'image: .\+:latest/, "Hostinger preflight must render the same Hostinger+WAF compose stack used by deploy and scan it for mutable images.");
  assertMatch(hostingerPostdeployScript, /get_env\(\)[\s\S]*awk -F=[\s\S]*env_or_default\(\)/, "Hostinger post-deploy must parse .env without executing it as a shell script.");
  assertNoMatch(hostingerPostdeployScript, /(?:^|\n)\s*\.\s+"\$ENV_FILE"|set -a[\s\S]*"\$ENV_FILE"/, "Hostinger post-deploy must not source .env.");
  assertMatch(hostingerPostdeployScript, /waf-smoke\.sh[\s\S]*infra-health\.sh[\s\S]*pre-go-live-evidence\.sh[\s\S]*secret-rotation-evidence\.sh --enforce[\s\S]*production-go-no-go\.sh --enforce[\s\S]*production-readiness-live\.sh/, "Hostinger post-deploy must cover smoke, health, optional pre go-live evidence, secret rotation evidence, final go/no-go and live production readiness.");
  assertMatch(hostingerGoLiveScript, /PLAN_ONLY=1[\s\S]*--confirmLive[\s\S]*PLAN_ONLY=0/, "Hostinger go-live orchestrator must be plan-only unless explicitly confirmed.");
  assertMatch(hostingerGoLiveScript, /vps-bootstrap-ubuntu\.sh --apply[\s\S]*vps-hardening-ubuntu\.sh --apply[\s\S]*vps-host-readiness\.sh --ssh-port \$SSH_PORT --enforce[\s\S]*hostinger-preflight\.sh[\s\S]*hostinger-postdeploy\.sh[\s\S]*github-actions-run-evidence\.sh[\s\S]*secret-rotation-evidence\.sh --enforce[\s\S]*production-go-no-go\.sh --enforce[\s\S]*production-readiness-live\.sh[\s\S]*evidence-bundle\.sh/, "Hostinger go-live orchestrator must sequence optional VPS bootstrap, hardening, readiness, preflight, postdeploy, GitHub Actions evidence, secret rotation evidence, go/no-go, live readiness and evidence bundle.");
  assertMatch(hostingerGoLiveScript, /evidence-bundle\.sh[\s\S]*evidence-bundle-verify\.sh --requireComplete/, "Hostinger go-live orchestrator must verify the final evidence bundle when go/no-go is enabled.");
  assertMatch(hostingerGoLiveScript, /--reload-sshd[\s\S]*RELOAD_SSHD=1[\s\S]*reloadSshd[\s\S]*vps-hardening-ubuntu\.sh --apply --ssh-port "\$SSH_PORT" \$reload_flag/, "Hostinger go-live orchestrator must expose explicit SSH reload for VPS hardening.");
  assertMatch(hostingerGoLiveScript, /--replace-docker-daemon-config[\s\S]*REPLACE_DOCKER_DAEMON_CONFIG=1[\s\S]*replaceDockerDaemonConfig[\s\S]*vps-hardening-ubuntu\.sh --apply --ssh-port "\$SSH_PORT" \$reload_flag --replace-docker-daemon-config/, "Hostinger go-live orchestrator must expose explicit Docker daemon config replacement for VPS hardening.");
  assertMatch(hostingerGoLiveScript, /REPLACE_DOCKER_DAEMON_CONFIG" -eq 1[\s\S]*APPLY_HARDENING" -ne 1[\s\S]*requires --apply-hardening/, "Hostinger go-live must reject Docker daemon replacement without --apply-hardening.");
  assertMatch(hostingerGoLiveScript, /RELOAD_SSHD" -eq 1[\s\S]*APPLY_HARDENING" -ne 1[\s\S]*requires --apply-hardening/, "Hostinger go-live must reject SSH reload without --apply-hardening.");
  assertMatch(hostingerGoLiveScript, /reports\/hostinger-go-live[\s\S]*JSON_REPORT[\s\S]*MD_REPORT/, "Hostinger go-live orchestrator must write JSON and Markdown reports.");
  assertNoMatch(hostingerGoLiveScript, /(?:^|\n)\s*\.\s+"\$ENV_FILE"|set -a[\s\S]*"\$ENV_FILE"|eval\s/, "Hostinger go-live orchestrator must not source/eval the production env file.");
  assertMatch(readme, /hostinger-preflight\.sh[\s\S]*compose\.waf\.yaml[\s\S]*compose\.hostinger-waf\.yaml/, "README must document that Hostinger preflight renders the WAF overlays.");
  assertMatch(runbook, /hostinger-preflight\.sh[\s\S]*compose\.waf\.yaml[\s\S]*compose\.hostinger-waf\.yaml/, "Runbook must document that Hostinger preflight renders the WAF overlays.");
  assertMatch(vpsPredeployChecklist, /hostinger-preflight\.sh[\s\S]*Hostinger\+WAF/, "VPS checklist must require Hostinger+WAF preflight coverage.");
  assertMatch(readme, /hostinger-postdeploy\.sh[\s\S]*DEPLOY_RUN_PRE_GO_LIVE/, "README must document Hostinger post-deploy evidence options.");
  assertMatch(runbook, /hostinger-postdeploy\.sh[\s\S]*DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN/, "Runbook must document Hostinger post-deploy evidence flags.");
  assertMatch(vpsPredeployChecklist, /hostinger-postdeploy\.sh[\s\S]*DEPLOY_RUN_GO_NO_GO/, "VPS checklist must require Hostinger post-deploy checks.");
  assertMatch(readme, /hostinger-go-live\.sh --planOnly[\s\S]*hostinger-go-live\.sh --confirmLive/, "README must document the Hostinger go-live orchestrator plan and live modes.");
  assertMatch(runbook, /hostinger-go-live\.sh --planOnly[\s\S]*hostinger-go-live\.sh --confirmLive/, "Runbook must document the Hostinger go-live orchestrator plan and live modes.");
  assertMatch(readme, /hostinger-go-live\.sh[\s\S]*--reload-sshd/, "README must document Hostinger go-live SSH reload mode.");
  assertMatch(runbook, /hostinger-go-live\.sh[\s\S]*--reload-sshd/, "Runbook must document Hostinger go-live SSH reload mode.");
  assertMatch(readme, /hostinger-go-live\.sh[\s\S]*--replace-docker-daemon-config/, "README must document Hostinger go-live Docker daemon replacement mode.");
  assertMatch(runbook, /hostinger-go-live\.sh[\s\S]*--replace-docker-daemon-config/, "Runbook must document Hostinger go-live Docker daemon replacement mode.");
  assertMatch(vpsPredeployChecklist, /hostinger-go-live\.sh --planOnly[\s\S]*reports\/hostinger-go-live/, "VPS checklist must require the Hostinger go-live plan report.");
  assertMatch(vpsPredeployChecklist, /hostinger-go-live\.sh --planOnly[\s\S]*--reload-sshd/, "VPS checklist must require reviewed planning for SSH reload.");
  assertMatch(vpsPredeployChecklist, /hostinger-go-live\.sh --planOnly[\s\S]*--replace-docker-daemon-config/, "VPS checklist must require reviewed planning for Docker daemon replacement.");
  assertMatch(evidenceBundleWrapper, /evidence-bundle/, "Evidence bundle wrapper must delegate to the Dockerized ops runner.");
  assertMatch(evidenceBundleVerifyWrapper, /evidence-bundle-verify/, "Evidence bundle verify wrapper must delegate to the Dockerized ops runner.");
  assertMatch(opsScript, /async function evidenceBundle[\s\S]*stexor-evidence-bundle-\$\{stamp\}[\s\S]*includesSecrets:\s+false/, "Ops script must create non-secret evidence bundles with a manifest.");
  assertMatch(opsScript, /async function evidenceBundleVerify[\s\S]*sha256 mismatch[\s\S]*required report is not passing[\s\S]*--requireComplete/, "Ops script must verify evidence bundle SHA256, report status and completeness.");
  assertMatch(githubActionsRunEvidenceWrapper, /github-actions-run-evidence/, "GitHub Actions run evidence wrapper must delegate to the Dockerized ops runner.");
  assertMatch(opsScript, /async function githubActionsRunEvidence[\s\S]*workflow_runs[\s\S]*run\.conclusion !== "success"/, "Ops script must verify remote GitHub Actions workflow success.");
  assertMatch(productionReadinessLiveWrapper, /enterprise-requirements-check --manifest governance\/production-readiness\.json --requireLiveProofs/, "Production readiness live wrapper must enforce the 20-point live checklist.");
  assertMatch(opsScript, /directory: "github-actions"[\s\S]*prefix: "github-actions-run-"[\s\S]*required: true/, "Evidence bundle must require the GitHub Actions run evidence report.");
  assertMatch(opsScript, /directory: "production-readiness"[\s\S]*prefix: "production-readiness-"[\s\S]*required: true/, "Evidence bundle must require the live production readiness report.");
  assertMatch(opsScript, /directory: "vps-bootstrap"[\s\S]*prefix: "vps-bootstrap-apply-"[\s\S]*required: true/, "Evidence bundle must require VPS bootstrap apply reports.");
  assertMatch(opsScript, /directory: "vps-hardening"[\s\S]*prefix: "vps-hardening-apply-"[\s\S]*required: true/, "Evidence bundle must require VPS hardening apply reports.");
  assertMatch(opsScript, /directory: "hostinger-go-live"[\s\S]*prefix: "hostinger-go-live-"/, "Evidence bundle must include Hostinger go-live orchestration reports when present.");
  assertMatch(opsScript, /"evidence-bundle": evidenceBundle/, "Ops command map must expose evidence-bundle.");
  assertMatch(readme, /evidence-bundle\.sh[\s\S]*\.tmp\/evidence-bundles/, "README must document the evidence bundle output.");
  assertMatch(readme, /evidence-bundle-verify\.sh --requireComplete[\s\S]*SHA256/, "README must document final evidence bundle verification.");
  assertMatch(runbook, /evidence-bundle\.sh[\s\S]*secrets\//, "Runbook must document evidence bundle secret exclusions.");
  assertMatch(runbook, /evidence-bundle-verify\.sh --requireComplete[\s\S]*SHA256/, "Runbook must document final evidence bundle verification.");
  assertMatch(vpsPredeployChecklist, /evidence-bundle\.sh[\s\S]*manifest\.json/, "VPS checklist must require the evidence bundle manifest review.");
  assertMatch(vpsPredeployChecklist, /evidence-bundle-verify\.sh --requireComplete/, "VPS checklist must require final evidence bundle verification.");
  assertMatch(readinessReport, /evidence-bundle\.sh[\s\S]*\.tmp\/evidence-bundles/, "Readiness report must include the evidence bundle command.");
  assertMatch(readinessReport, /evidence-bundle-verify\.sh --requireComplete/, "Readiness report must include final evidence bundle verification.");
  assertMatch(readinessReport, /hostinger-postdeploy\.sh[\s\S]*production-go-no-go/, "Readiness report must include Hostinger post-deploy and go/no-go flow.");
  assertMatch(finalReadinessAudit, /evidence-bundle\.sh[\s\S]*SHA256/, "Final readiness audit must include evidence bundle and checksum evidence.");
  assertMatch(finalReadinessAudit, /Evidence bundle verifier[\s\S]*SHA256/, "Final readiness audit must include evidence bundle verifier coverage.");
  assertMatch(finalReadinessAudit, /hostinger-postdeploy\.sh[\s\S]*infra-health/, "Final readiness audit must include Hostinger post-deploy health checks.");
  assertMatch(finalReadinessAudit, /mode=dry-run[\s\S]*providerEvidence\.verified=false/, "Final readiness audit must document uptime dry-run evidence semantics.");
  assertMatch(externalUptimeManifest, /api-public-health[\s\S]*API_PUBLIC_URL/, "External uptime manifest must monitor the public API health endpoint.");
  assertMatch(externalUptimeManifest, /keycloak-issuer-discovery[\s\S]*KEYCLOAK_ISSUER/, "External uptime manifest must monitor OIDC issuer discovery.");
  assertMatch(externalUptimeManifest, /blocked-phpmyadmin-public[\s\S]*blocked-prometheus-public[\s\S]*blocked-alertmanager-public/, "External uptime manifest must assert public admin hosts stay blocked.");
  assertMatch(externalUptimeManifest, /providerNotes[\s\S]*cloudflare[\s\S]*betterstack[\s\S]*uptimerobot/, "External uptime manifest must map to common external monitoring providers.");
  assertMatch(externalUptimeWrapper, /external-uptime-check/, "External uptime wrapper must delegate to the Dockerized ops runner.");
  assertMatch(opsScript, /async function externalUptimeCheck/, "Ops script must provide an external uptime monitor check.");
  assertMatch(opsScript, /expectedBodyIncludes[\s\S]*maxLatencyMs/, "External uptime check must support body and latency assertions.");
  assertMatch(opsScript, /function validateExternalUptimeProviderEvidence[\s\S]*external=true[\s\S]*coveredTargets/, "External uptime evidence must validate a real external provider monitor set.");
  assertMatch(opsScript, /monitorTimestamp[\s\S]*lastCheckedAt[\s\S]*providerMonitorResult[\s\S]*lastStatusCode[\s\S]*lastLatencyMs/, "External uptime provider evidence must validate fresh provider-reported status, latency and check time.");
  assertMatch(opsScript, /uptimeProviderVerified[\s\S]*providerEvidence\?\.verified === true/, "Production go/no-go must require external uptime provider evidence.");
  assertMatch(opsScript, /validateProviderEvidenceOnly[\s\S]*validateExternalUptimeProviderEvidence[\s\S]*writeExternalUptimeReport/, "External uptime provider-only validation must write an evidence report without probing public URLs.");
  assertMatch(opsScript, /mode:\s*"dry-run"[\s\S]*External uptime dry-run reports written/, "External uptime dry-run must write diagnostic reports.");
  assertMatch(cloudflareAccessManifest, /"mfaEnforcedByIdentityProvider": true/, "Cloudflare Access manifest must require IdP MFA.");
  assertMatch(cloudflareAccessManifest, /"allowedIdentityProviderIds"[\s\S]*"applications"/, "Cloudflare Access manifest must define identity providers and protected applications.");
  for (const host of ["grafana", "prometheus", "alertmanager", "minio", "traefik", "phpmyadmin", "projects", "keycloak-admin"]) {
    if (!cloudflareAccess.applications.some((app) => String(app.domain).startsWith(`${host}.`))) {
      fail(`Cloudflare Access manifest must protect ${host}.`);
    }
  }
  assertMatch(cloudflareAccessScript, /\/accounts\/\$\{manifest\.accountId\}\/access\/apps/, "Cloudflare Access script must use the account Access applications API.");
  assertMatch(cloudflareAccessScript, /enable_binding_cookie[\s\S]*http_only_cookie_attribute[\s\S]*same_site_cookie_attribute/, "Cloudflare Access applications must use hardened cookies.");
  assertMatch(cloudflareAccessScript, /login_method/, "Cloudflare Access policies must require the configured identity provider.");
  assertMatch(cloudflareAccessScript, /reports"[\s\S]*"cloudflare-access"[\s\S]*writeEvidenceReport/, "Cloudflare Access admin command must write file-based evidence.");
  assertMatch(cloudflareAccessScript, /catch \(error\)[\s\S]*writeEvidenceReport\(\{[\s\S]*status: "failed"[\s\S]*error\.applications/, "Cloudflare Access admin command must write failed remote verification evidence.");
  assertMatch(cloudflareReadme, /access-admin\.example\.json[\s\S]*cloudflare-access-admin\.sh/, "Cloudflare docs must cover the Access admin policy manifest.");
  assertMatch(opsScript, /async function cloudflareAccessAdmin/, "Ops script must expose the Cloudflare Access admin command.");
  assertMatch(opsScript, /"cloudflare-access-admin": cloudflareAccessAdmin/, "Ops command map must expose cloudflare-access-admin.");
  assertMatch(githubWorkflow, /Cloudflare Access admin dry run[\s\S]*cloudflare-access-admin/, "Infrastructure CI must validate the Cloudflare Access admin manifest.");
  assertMatch(cloudflareWafRules, /stexor-block-admin-hosts/, "Cloudflare WAF rules must block public admin hostnames.");
  assertMatch(cloudflareWafRules, /stexor-block-sensitive-files/, "Cloudflare WAF rules must block sensitive file probes.");
  assertMatch(cloudflareSettings, /always_use_https/, "Cloudflare zone settings must require HTTPS redirect configuration.");
  if (cloudflareFromZero.requireEmptyDns !== true) {
    fail("Cloudflare from-zero manifest must require an empty DNS zone by default.");
  }
  assertMatch(cloudflareReadme, /additive-only/, "Cloudflare README must document additive-only live changes.");
  assertMatch(cloudflareReadme, /Zone settings[\s\S]*only when the zone is created by the same script run/, "Cloudflare README must prevent settings changes on existing zones.");
  assertMatch(cloudflareFromZeroScript, /Mode: dry-run/, "Cloudflare from-zero script must default to dry-run.");
  assertMatch(cloudflareFromZeroScript, /Refusing DNS conflict/, "Cloudflare from-zero script must refuse conflicting DNS records.");
  assertMatch(cloudflareFromZeroScript, /DNS already exists unchanged; left untouched/, "Cloudflare from-zero script must leave exact existing DNS records untouched.");
  assertMatch(cloudflareFromZeroScript, /Refusing to change Cloudflare zone settings on an existing zone/, "Cloudflare from-zero script must not change settings on existing zones.");
  assertMatch(cloudflareFromZeroScript, /method:\s+"POST"[\s\S]*path:\s+`\/zones\/\$\{zone\.id\}\/rulesets`/, "Cloudflare from-zero script must create, not update, the WAF entrypoint.");
  assertNoMatch(cloudflareFromZeroScript, /method:\s+"(?:PUT|DELETE)"/, "Cloudflare from-zero script must not use destructive or overwrite API verbs.");
  assertNoMatch(cloudflareFromZeroScript, /dns_records\/\$\{/, "Cloudflare from-zero script must not target existing DNS record IDs.");
  assertNoMatch(cloudflareFromZeroScript, /rulesets\/phases\/\$\{ruleset\.phase\}\/entrypoint/, "Cloudflare from-zero script must not overwrite a WAF phase entrypoint.");
  assertMatch(vpsBootstrapScript, /download\.docker\.com\/linux\/ubuntu[\s\S]*docker-ce[\s\S]*docker-ce-cli[\s\S]*containerd\.io[\s\S]*docker-buildx-plugin[\s\S]*docker-compose-plugin/, "VPS bootstrap must install Docker Engine, Buildx and Compose from Docker's official Ubuntu apt repository.");
  assertMatch(vpsBootstrapScript, /ca-certificates curl git[\s\S]*\/etc\/apt\/keyrings\/docker\.asc[\s\S]*\/etc\/apt\/sources\.list\.d\/docker\.sources/, "VPS bootstrap must install Git and configure the Docker apt keyring/source file.");
  assertMatch(vpsBootstrapScript, /reports\/vps-bootstrap[\s\S]*JSON_REPORT[\s\S]*MD_REPORT/, "VPS bootstrap must write JSON and Markdown evidence reports.");
  assertMatch(vpsBootstrapScript, /os_release_value\(\)[\s\S]*awk -F=[\s\S]*\/etc\/os-release/, "VPS bootstrap must parse /etc/os-release as data.");
  assertNoMatch(vpsBootstrapScript, /(^|\n)\s*\.\s+\/etc\/os-release/, "VPS bootstrap must not source /etc/os-release.");
  assertMatch(vpsBootstrapScript, /APPLY=0[\s\S]*--apply[\s\S]*APPLY=1[\s\S]*apply mode requires root/, "VPS bootstrap must default to plan mode and require root only for apply.");
  assertMatch(vpsHardeningScript, /PasswordAuthentication no/, "VPS hardening must disable SSH password authentication.");
  assertMatch(vpsHardeningScript, /--reload-sshd[\s\S]*sshd -t[\s\S]*ssh-service-reload[\s\S]*systemctl reload ssh/, "VPS hardening must validate and reload SSH only when explicitly requested.");
  assertMatch(vpsHardeningScript, /fail2ban/, "VPS hardening must install fail2ban.");
  assertMatch(vpsHardeningScript, /reports\/vps-hardening[\s\S]*JSON_REPORT[\s\S]*MD_REPORT/, "VPS hardening must write JSON and Markdown evidence reports.");
  assertMatch(vpsHardeningScript, /daemon_contains_hardening\(\)[\s\S]*live-restore[\s\S]*no-new-privileges[\s\S]*max-size[\s\S]*max-file/, "VPS hardening must verify Docker daemon hardening keys.");
  assertMatch(vpsHardeningScript, /--replace-docker-daemon-config[\s\S]*daemon\.json\.stexor-backup-\$STAMP[\s\S]*write_file "\$daemon_path" 0644 "\$DOCKER_DAEMON_CONFIG"/, "VPS hardening must safely apply Docker daemon hardening with backup support.");
  assertMatch(vpsHardeningScript, /restart_docker_if_changed\(\)[\s\S]*systemctl restart docker/, "VPS hardening must restart Docker after applying daemon hardening when the service exists.");
  assertMatch(vpsHardeningScript, /APPLY=0[\s\S]*--apply[\s\S]*APPLY=1[\s\S]*REPORT_PREFIX="vps-hardening-plan"[\s\S]*REPORT_PREFIX="vps-hardening-apply"[\s\S]*printf apply \|\| printf plan/, "VPS hardening must default to a plan and distinguish apply evidence.");
  assertMatch(vpsHardeningScript, /apply mode requires root[\s\S]*write_reports/, "VPS hardening apply mode must require root and write failed evidence.");
  assertMatch(vpsHostReadinessScript, /os_release_value\(\)[\s\S]*awk -F=[\s\S]*\/etc\/os-release[\s\S]*ubuntu[\s\S]*lts/i, "VPS host readiness must verify Ubuntu LTS by parsing /etc/os-release as data.");
  assertNoMatch(vpsHostReadinessScript, /(^|\n)\s*\.\s+\/etc\/os-release/, "VPS host readiness must not source /etc/os-release.");
  assertMatch(vpsHostReadinessScript, /docker compose version/, "VPS host readiness must verify Docker Compose plugin.");
  assertMatch(vpsHostReadinessScript, /ufw status verbose[\s\S]*ufw-no-direct-internal-ports/, "VPS host readiness must verify UFW and blocked internal ports.");
  assertMatch(vpsHostReadinessScript, /--ssh-port[\s\S]*EXPECTED_SSH_PORT[\s\S]*expectedSshPort/, "VPS host readiness must expose and report the expected hardened SSH port.");
  assertMatch(vpsHostReadinessScript, /ufw-ssh-port-allowed[\s\S]*ssh-port-expected/, "VPS host readiness must verify UFW allows and sshd listens on the expected SSH port.");
  assertMatch(vpsHostReadinessScript, /fail2ban[\s\S]*sshd -T/, "VPS host readiness must verify fail2ban and SSH hardening.");
  assertMatch(vpsHostReadinessScript, /docker-daemon-hardening[\s\S]*live-restore[\s\S]*no-new-privileges/, "VPS host readiness must verify Docker daemon hardening.");
  assertMatch(vpsHostReadinessScript, /--enforce[\s\S]*ALLOW_FAILURES=0/, "VPS host readiness must expose an explicit enforce mode for production evidence.");
  assertMatch(vpsHostReadinessScript, /--diagnostic[\s\S]*reports\/vps-host-diagnostics[\s\S]*productionEvidence[\s\S]*false/, "VPS host readiness diagnostics must be separated from production VPS evidence.");
  assertMatch(vpsHostReadinessScript, /DEFAULT_REPORT_DIR="\$ROOT_DIR\/reports\/vps-host"[\s\S]*JSON_REPORT="\$REPORT_DIR\/\$REPORT_PREFIX-\$STAMP\.json"[\s\S]*MD_REPORT="\$REPORT_DIR\/\$REPORT_PREFIX-\$STAMP\.md"/, "VPS host readiness must write ignored JSON and Markdown evidence.");
  assertMatch(vpsHostReadinessScript, /remediation_for_check[\s\S]*docker-daemon-hardening[\s\S]*vps-hardening-ubuntu\.sh/, "VPS host readiness reports must include remediation guidance.");
  assertMatch(originLockScript, /www\.cloudflare\.com\/ips-v4/, "Origin-lock script must consume Cloudflare IPv4 ranges.");
  assertMatch(originLockScript, /www\.cloudflare\.com\/ips-v6/, "Origin-lock script must consume Cloudflare IPv6 ranges.");
  assertMatch(vpsPredeployChecklist, /full-restore-drill\.sh/, "VPS checklist must require a full restore drill.");
  assertMatch(vpsPredeployChecklist, /offsite-backup-restic\.sh/, "VPS checklist must require off-site backup upload.");
  assertMatch(vpsPredeployChecklist, /Cloudflare Access, VPN, SSH tunnel/, "VPS checklist must protect admin surfaces.");
  assertMatch(vpsPredeployChecklist, /cloudflare-access-admin\.sh --verifyRemote/, "VPS checklist must verify Cloudflare Access admin applications.");
  assertMatch(vpsPredeployChecklist, /Node, pnpm, PHP CLI and build toolchains are not required on the host/, "VPS checklist must keep host dependencies limited to Docker, Compose and Git.");
  assertMatch(vpsPredeployChecklist, /compose\.backup-scheduler\.yaml/, "VPS checklist must require the Dockerized backup scheduler or approved equivalent.");
  assertMatch(readme, /vps-bootstrap-ubuntu\.sh[\s\S]*reports\/vps-bootstrap/, "README must document VPS bootstrap evidence reports.");
  assertMatch(runbook, /vps-bootstrap-ubuntu\.sh[\s\S]*reports\/vps-bootstrap/, "Runbook must document VPS bootstrap evidence reports.");
  assertMatch(vpsPredeployChecklist, /vps-bootstrap-ubuntu\.sh[\s\S]*reports\/vps-bootstrap/, "VPS checklist must require VPS bootstrap evidence reports.");
  assertMatch(readme, /vps-hardening-ubuntu\.sh[\s\S]*reports\/vps-hardening/, "README must document VPS hardening evidence reports.");
  assertMatch(runbook, /vps-hardening-ubuntu\.sh[\s\S]*reports\/vps-hardening/, "Runbook must document VPS hardening evidence reports.");
  assertMatch(vpsPredeployChecklist, /vps-hardening-ubuntu\.sh[\s\S]*reports\/vps-hardening/, "VPS checklist must require VPS hardening evidence reports.");
  assertMatch(readme, /vps-host-readiness\.sh[\s\S]*reports\/vps-host/, "README must document VPS host readiness evidence reports.");
  assertMatch(runbook, /vps-host-readiness\.sh[\s\S]*reports\/vps-host/, "Runbook must document VPS host readiness evidence reports.");
  assertMatch(vpsPredeployChecklist, /vps-host-readiness\.sh[\s\S]*reports\/vps-host/, "VPS checklist must require VPS host readiness evidence.");
  assertMatch(finalReadinessAudit, /VPS host readiness script/, "Final readiness audit must include the VPS host readiness script.");
  assertMatch(readinessReport, /Requires Real VPS Or External Provider/, "Readiness report must separate repo-ready work from VPS/provider work.");
  assertMatch(readinessReport, /load-benchmark\.sh --profiles 50,100,500/, "Readiness report must include the 50/100/500 load benchmark.");
  assertMatch(readinessReport, /Containerized ops runner/, "Readiness report must record that host Node is not required.");
  assertMatch(readinessReport, /cross-platform Dockerized infra-ops launcher/, "Readiness report must record the Docker Desktop application launcher.");
  assertMatch(readinessReport, /Cloudflare Access admin manifest/, "Readiness report must record the Cloudflare Access manifest.");
  assertMatch(finalReadinessAudit, /Cloudflare Access admin application/, "Final audit must record Cloudflare Access admin application evidence.");
  assertMatch(readinessReport, /Dockerized backup scheduler profile/, "Readiness report must record the Dockerized backup scheduler.");
  assertMatch(readme, /reports\/backups/, "README must document backup execution reports.");
  assertMatch(runbook, /reports\/backups/, "Runbook must document backup execution reports.");
  assertMatch(readme, /dr-evidence\.sh[\s\S]*RTO\/RPO/, "README must document DR evidence RTO/RPO summaries.");
  assertMatch(runbook, /dr-evidence\.sh[\s\S]*--enforce/, "Runbook must document enforced DR evidence checks.");
  assertMatch(vpsPredeployChecklist, /dr-evidence\.sh --enforce[\s\S]*reports\/dr/, "VPS checklist must require enforced DR evidence reports.");
  assertMatch(finalReadinessAudit, /DR evidence summary/, "Final readiness audit must mention DR evidence summaries.");
  assertMatch(readme, /alert-evidence\.sh[\s\S]*--sendTest/, "README must document alert evidence runtime testing.");
  assertMatch(runbook, /Alert evidence:[\s\S]*alert-evidence\.sh --sendTest/, "Runbook must document alert evidence runtime testing.");
  assertMatch(vpsPredeployChecklist, /alert-evidence\.sh --sendTest --requireEmailDelivery[\s\S]*reports\/alerts/, "VPS checklist must require alert delivery evidence reports.");
  assertMatch(readinessReport, /alert-evidence\.sh/, "Readiness report must include alert evidence tooling.");
  assertMatch(finalReadinessAudit, /Alert evidence command/, "Final readiness audit must mention alert evidence tooling.");
  assertMatch(readme, /monitoring\/external-uptime\.example\.json[\s\S]*external-uptime-check\.sh --dryRun/, "README must document external uptime manifest validation.");
  assertMatch(readme, /mode=dry-run[\s\S]*production go[/-]no-go/, "README must explain that uptime dry-run reports do not satisfy production go/no-go.");
  assertMatch(runbook, /External uptime monitoring[\s\S]*external-uptime-check\.sh --dryRun/, "Runbook must document external uptime monitoring setup.");
  assertMatch(runbook, /mode=dry-run[\s\S]*production go[/-]no-go/, "Runbook must explain that uptime dry-run reports do not satisfy production go/no-go.");
  assertMatch(vpsPredeployChecklist, /external-uptime-check\.sh --dryRun[\s\S]*External uptime monitoring delivered a real green check/, "VPS checklist must include external uptime dry-run and provider confirmation.");
  assertMatch(readme, /github-branch-protection\.sh[\s\S]*--verifyRemote/, "README must document GitHub branch protection apply/verify.");
  assertMatch(runbook, /github-branch-protection\.sh[\s\S]*--apply[\s\S]*--verifyRemote/, "Runbook must document GitHub branch protection apply and remote verification.");
  assertMatch(vpsPredeployChecklist, /github-branch-protection\.sh[\s\S]*--verifyRemote/, "VPS checklist must require live GitHub branch protection verification.");
  assertMatch(readme, /github-environments\.sh[\s\S]*GITHUB_PRODUCTION_REVIEWERS[\s\S]*--verifyRemote/, "README must document GitHub deployment environments apply/verify.");
  assertMatch(runbook, /github-environments\.sh[\s\S]*GITHUB_PRODUCTION_REVIEWERS[\s\S]*--verifyRemote/, "Runbook must document GitHub deployment environments apply and remote verification.");
  assertMatch(vpsPredeployChecklist, /github-environments\.sh[\s\S]*--verifyRemote/, "VPS checklist must require live GitHub deployment environment verification.");
  assertMatch(readme, /github-actions-config\.sh[\s\S]*DEPLOY_SSH_KEY[\s\S]*--verifyRemote/, "README must document GitHub Actions runtime config verification.");
  assertMatch(readme, /github-actions-run-evidence\.sh[\s\S]*reports\/github-actions/, "README must document GitHub Actions run evidence.");
  assertMatch(runbook, /github-actions-config\.sh[\s\S]*DEPLOY_SSH_KEY/, "Runbook must document required GitHub Actions runtime secrets and variables.");
  assertMatch(runbook, /github-actions-run-evidence\.sh[\s\S]*reports\/github-actions/, "Runbook must document GitHub Actions run evidence.");
  assertMatch(vpsPredeployChecklist, /github-actions-config\.sh[\s\S]*DEPLOY_REMOTE_DIR/, "VPS checklist must require live GitHub Actions runtime config verification.");
  assertMatch(vpsPredeployChecklist, /github-actions-run-evidence\.sh[\s\S]*reports\/github-actions/, "VPS checklist must require GitHub Actions run evidence.");
  assertMatch(readme, /pre-go-live-evidence\.sh[\s\S]*reports\/go-live/, "README must document the pre go-live evidence pack.");
  assertMatch(runbook, /pre-go-live-evidence\.sh[\s\S]*includeRuntime[\s\S]*includeRestoreDrill/, "Runbook must document runtime and restore evidence options.");
  assertMatch(vpsPredeployChecklist, /pre-go-live-evidence\.sh[\s\S]*reports\/go-live/, "VPS checklist must require the go-live evidence report.");
  assertMatch(opsScript, /const readinessMissing = readinessMatrix\.filter[\s\S]*missingOptions[\s\S]*status: issues\.length \? "failed" : "passed"/, "Pre go-live evidence must write status, missing options and readiness issues.");
  assertMatch(opsScript, /preGoLive\.payload\.status === "passed"/, "Production go/no-go must require passed pre go-live evidence.");
  assertMatch(readme, /release-evidence\.sh[\s\S]*reports\/release/, "README must document release evidence reports.");
  assertMatch(runbook, /release-evidence\.sh[\s\S]*reports\/release/, "Runbook must document release evidence reports.");
  assertMatch(vpsPredeployChecklist, /release-evidence\.sh[\s\S]*reports\/release/, "VPS checklist must require release evidence reports.");
  assertMatch(readinessReport, /release-evidence\.sh/, "Readiness report must include release evidence tooling.");
  assertMatch(readme, /production-go-no-go\.sh[\s\S]*reports\/go-no-go/, "README must document the production go/no-go evidence gate.");
  assertMatch(runbook, /Production go\/no-go[\s\S]*production-go-no-go\.sh --enforce/, "Runbook must document enforcing the production go/no-go gate.");
  assertMatch(vpsPredeployChecklist, /production-go-no-go\.sh --enforce[\s\S]*reports\/go-no-go/, "VPS checklist must require the production go/no-go report.");
  assertMatch(readme, /production-readiness-live\.sh[\s\S]*reports\/production-readiness/, "README must document the live production readiness gate.");
  assertMatch(runbook, /production-readiness-live\.sh[\s\S]*reports\/production-readiness/, "Runbook must document the live production readiness gate.");
  assertMatch(vpsPredeployChecklist, /production-readiness-live\.sh[\s\S]*reports\/production-readiness/, "VPS checklist must require the live production readiness report.");
  assertMatch(readinessReport, /production-go-no-go\.sh/, "Readiness report must include production go/no-go tooling.");
  assertMatch(finalReadinessAudit, /production-go-no-go/, "Final readiness audit must mention the production go/no-go gate.");
  assertMatch(readinessReport, /production-readiness-live\.sh/, "Readiness report must include live production readiness tooling.");
  assertMatch(finalReadinessAudit, /production-readiness/, "Final readiness audit must mention the live production readiness report.");
  assertMatch(readme, /linux-portability-check\.sh[\s\S]*reports\/linux-portability/, "README must document Linux portability evidence reports.");
  assertMatch(runbook, /Linux portability[\s\S]*linux-portability-check\.sh --fix/, "Runbook must document the Linux portability check and fix mode.");
  assertMatch(vpsPredeployChecklist, /linux-portability-check\.sh[\s\S]*reports\/linux-portability/, "VPS checklist must require Linux portability evidence reports.");
  assertMatch(readinessReport, /linux-portability-check\.sh/, "Readiness report must include Linux portability tooling.");
  assertMatch(finalReadinessAudit, /linux-portability-check/, "Final readiness audit must mention the Linux portability gate.");
  assertMatch(readme, /offsite-restore-drill-restic\.sh[\s\S]*--dryRun/, "README must document the off-site Restic restore drill dry-run.");
  assertMatch(runbook, /Off-site restore drill[\s\S]*offsite-restore-drill-restic\.sh/, "Runbook must document the off-site Restic restore drill.");
  assertMatch(vpsPredeployChecklist, /offsite-restore-drill-restic\.sh[\s\S]*off-site repository/, "VPS checklist must require the off-site restore drill.");
  assertMatch(finalReadinessAudit, /offsite-restore-drill-restic/, "Final readiness audit must mention the off-site Restic restore drill.");
  assertMatch(finalReadinessAudit, /## Modified Files[\s\S]*## New Components[\s\S]*## Tests Executed[\s\S]*## Problems Found And Fixed/, "Final readiness audit must include files, components, tests and problems.");
  assertMatch(finalReadinessAudit, /## Requirement Status[\s\S]*## Readiness Scores[\s\S]*## Requires Real VPS Or External Provider[\s\S]*## Final VPS Pre-Deploy Checklist/, "Final readiness audit must include requirement status, scores, VPS-only work and checklist.");
  assertMatch(finalReadinessAudit, /Dockerized backup scheduler/, "Final readiness audit must include the Dockerized backup scheduler.");
  assertMatch(readme, /Docker Engine, Docker Compose plugin e Git/, "README must document the minimal Hostinger host dependency set.");
  assertMatch(readme, /compose\.backup-scheduler\.yaml[\s\S]*--profile backup/, "README must document enabling the Dockerized backup scheduler.");
  assertMatch(runbook, /docker exec enterprise-backup-scheduler crontab -l/, "Runbook must document verifying the backup scheduler crontab.");
  assertMatch(envExample, /BACKUP_SCHEDULER_POSTGRES_AT[\s\S]*BACKUP_SCHEDULER_ENABLE_OFFSITE/, ".env.example must expose backup scheduler timing and off-site toggles.");
  assertNoMatch(`${readme}\n${runbook}\n${enterprisePlan}`, /node\s+(?:\.\/)?scripts\/stexor-ops\.mjs/, "Infra operator docs must use the Dockerized ops wrapper, not host Node.");
  const secretInterpolationPattern = /\b(?:POSTGRES_PASSWORD|APP_DB_PASSWORD|KEYCLOAK_DB_PASSWORD|REDIS_PASSWORD|KC_BOOTSTRAP_ADMIN_PASSWORD|KC_DB_PASSWORD|NATS_PASSWORD|MINIO_ROOT_PASSWORD|SESSION_SECRET|SESSION_SIGNING_KEYS|SECRET_HASH_KEYS|DATABASE_URL|NATS_URL|SMTP_PASSWORD|GF_SECURITY_ADMIN_PASSWORD|GOOGLE_RECAPTCHA_SECRET_KEY|CLOUDFLARE_TURNSTILE_SECRET_KEY|GOOGLE_OAUTH_CLIENT_SECRET)\s*:\s*\$\{/;
  for (const [label, text] of [["compose.yaml", compose], ["compose.prod.yaml", composeProd], ["compose.secrets.yaml", composeSecrets]]) {
    assertNoMatch(text, secretInterpolationPattern, `${label} must not interpolate secret values from process environment.`);
  }
  assertNoMatch(observabilitySource, /env\.NODE_ENV[\s\S]*env\[name\]/, "Shared secret reader must not fall back to process environment secret values.");
  assertNoMatch(e2eStackHelper, /\$(?:SESSION_SECRET|SECRET_HASH_KEYS|REDIS_PASSWORD)\b/, "E2E stack helpers must read runtime secrets through Docker secret files only.");
  assertNoMatch(secretManagerScript, /value(?:E|[-]e)nv/, "Stexor Secret Manager imports must not accept secret values from process environment variables.");
  assertMatch(secretManagerScript, /manager:\s+"stexor-secret-manager"/, "Infrastructure must include the proprietary Stexor Secret Manager store format.");
  assertMatch(secretManagerScript, /stexor-local-kms/, "Stexor Secret Manager must use the proprietary Stexor Local KMS envelope layer.");
  assertMatch(secretManagerScript, /HKDF-SHA256\+A256GCM/, "Stexor Local KMS must derive per-key encryption keys for envelope encryption.");
  assertMatch(secretManagerScript, /kms-rotate/, "Stexor Local KMS must expose an operational key rotation command.");
  assertMatch(secretManagerScript, /AES-256-GCM/, "Stexor Secret Manager must encrypt stored secrets with authenticated encryption.");
  assertMatch(secretManagerScript, /function audit\(/, "Stexor Secret Manager must append an audit trail for secret operations.");
  assertMatch(secretManagerScript, /function materialize\(/, "Stexor Secret Manager must materialize Docker secret files for Compose.");
  assertMatch(secretManagerScript, /mariadb_root_password[\s\S]*phpmyadmin_control_password/, "Stexor Secret Manager must manage MariaDB and phpMyAdmin local Docker secrets.");
  assertMatch(opsScript, /runSecretManager\(\["verify"/, "Enterprise local secret validation must verify the proprietary secret manager store.");
  assertMatch(secretRotationEvidenceWrapper, /secret-rotation-evidence/, "Secret rotation evidence wrapper must delegate to the Dockerized ops runner.");
  assertMatch(opsScript, /async function secretRotationEvidence[\s\S]*verify\.status[\s\S]*expiredSecrets/, "Ops script must write a secret rotation/freshness evidence report without secret values.");
  assertMatch(opsScript, /latestJsonReport\("secret-rotation", "secret-rotation-evidence-"/, "Production go/no-go must evaluate secret rotation evidence.");
  assertMatch(productionGoNoGoPolicyText, /"requireSecretRotationEvidence":\s*true/, "Production go/no-go policy must require a secret rotation evidence report.");
  assertMatch(productionGoNoGoPolicyText, /"secretRotation":\s*24/, "Production go/no-go policy must require fresh secret rotation evidence.");
  assertMatch(productionReadinessManifest, /"secrets-management"[\s\S]*"secret-rotation-evidence"/, "Production readiness must map secrets management to dedicated secret rotation evidence.");
  assertMatch(composeDr, /archive_mode=on/, "DR overlay must enable PostgreSQL WAL archiving.");
  assertMatch(composeDr, /enterprise_postgres_wal_archive/, "DR overlay must persist WAL archives.");
  assertMatch(admissionPolicy, /cosign\.sigstore\.dev\/verified/, "Admission policy must require cosign verification.");
  assertMatch(admissionPolicy, /slsa\.dev\/provenance/, "Admission policy must require SLSA provenance.");
  assertMatch(branchProtection, /enterprise-readiness/, "Governance branch protection must require enterprise-readiness.");
  assertMatch(githubBranchProtectionWrapper, /github-branch-protection/, "GitHub branch protection wrapper must delegate to the Dockerized ops runner.");
  assertMatch(githubEnvironmentsWrapper, /github-environments/, "GitHub environments wrapper must delegate to the Dockerized ops runner.");
  assertMatch(githubActionsConfigWrapper, /github-actions-config/, "GitHub Actions config wrapper must delegate to the Dockerized ops runner.");
  assertMatch(preGoLiveEvidenceWrapper, /pre-go-live-evidence/, "Pre go-live evidence wrapper must delegate to the Dockerized ops runner.");
  if (!githubEnvironmentsPolicyJson.environments?.some((environment) => environment.name === "staging")) {
    fail("Governance GitHub environments policy must define staging.");
  }
  const productionEnvironment = githubEnvironmentsPolicyJson.environments?.find((environment) => environment.name === "production");
  if (!productionEnvironment) {
    fail("Governance GitHub environments policy must define production.");
  }
  if (productionEnvironment.required_reviewers_env !== "GITHUB_PRODUCTION_REVIEWERS" || !productionEnvironment.require_reviewers_on_apply) {
    fail("Production GitHub environment must require deployment reviewers through GITHUB_PRODUCTION_REVIEWERS.");
  }
  assertMatch(githubEnvironmentsPolicyText, /"wait_timer":\s*15[\s\S]*"protected_branches":\s*true[\s\S]*"custom_branch_policies":\s*false/, "Production GitHub environment must require a wait timer and protected branches.");
  if (githubActionsRuntimePolicyJson.repository?.required_secrets?.some((secret) => secret.name === "STEXOR_APP_REPO_TOKEN")) {
    fail("GitHub Actions runtime policy must not require STEXOR_APP_REPO_TOKEN.");
  }
  const stagingRuntime = githubActionsRuntimePolicyJson.environments?.find((environment) => environment.name === "staging");
  const productionRuntime = githubActionsRuntimePolicyJson.environments?.find((environment) => environment.name === "production");
  if (!stagingRuntime?.required_variables?.some((variable) => variable.name === "DAST_TARGET")) {
    fail("GitHub Actions runtime policy must require DAST_TARGET in staging.");
  }
  if (!productionRuntime?.required_secrets?.some((secret) => secret.name === "DEPLOY_SSH_KEY")) {
    fail("GitHub Actions runtime policy must require DEPLOY_SSH_KEY in production.");
  }
  for (const name of ["DEPLOY_REMOTE", "DEPLOY_REMOTE_DIR"]) {
    if (!productionRuntime?.required_variables?.some((variable) => variable.name === name)) {
      fail(`GitHub Actions runtime policy must require ${name} in production.`);
    }
  }
  assertMatch(githubActionsRuntimePolicyText, /"DEPLOY_REMOTE"[\s\S]*"DEPLOY_REMOTE_DIR"/, "GitHub Actions runtime policy must define production deploy destination variables.");
  assertMatch(opsScript, /async function githubBranchProtection/, "Ops script must provide a GitHub branch protection command.");
  assertMatch(opsScript, /Mode: dry-run[\s\S]*--apply/, "GitHub branch protection command must default to dry-run and require explicit apply.");
  assertMatch(opsScript, /GITHUB_TOKEN[\s\S]*GH_TOKEN[\s\S]*Authorization[\s\S]*Bearer \$\{token\}/, "GitHub branch protection command must use token-authenticated GitHub API calls.");
  assertMatch(opsScript, /githubApi\("PUT", apiPath, policy\)/, "GitHub branch protection command must update the live policy only through the explicit apply path.");
  assertMatch(opsScript, /"github-branch-protection": githubBranchProtection/, "Ops command map must expose github-branch-protection.");
  assertMatch(opsScript, /async function githubEnvironments/, "Ops script must provide a GitHub environments command.");
  assertMatch(opsScript, /required_reviewers_env[\s\S]*require_reviewers_on_apply/, "GitHub environments command must support reviewer env vars and apply-time enforcement.");
  assertMatch(opsScript, /githubApi\("PUT", githubEnvironmentApiPath\(repo, environment\.name\), payload\)/, "GitHub environments command must update live environments only through the explicit apply path.");
  assertMatch(opsScript, /"github-environments": githubEnvironments/, "Ops command map must expose github-environments.");
  assertMatch(githubWorkflow, /GitHub environments dry run/, "Infra workflow must dry-run GitHub environment policy.");
  assertMatch(opsScript, /async function githubActionsConfig/, "Ops script must provide a GitHub Actions runtime config command.");
  assertMatch(opsScript, /githubApiList\(`\$\{basePath\}\/actions\/secrets`, "secrets"\)/, "GitHub Actions config command must verify repository secrets through the GitHub API.");
  assertMatch(opsScript, /validateVariablePatterns/, "GitHub Actions config command must validate variable formats without printing secret values.");
  assertMatch(opsScript, /"github-actions-config": githubActionsConfig/, "Ops command map must expose github-actions-config.");
  assertMatch(githubWorkflow, /GitHub Actions runtime config dry run[\s\S]*github-actions-config --repo/, "Infra workflow must dry-run GitHub Actions runtime config policy.");
  assertMatch(githubWorkflow, /GitHub Actions run evidence plan[\s\S]*github-actions-run-evidence/, "Infra workflow must generate a GitHub Actions run evidence plan.");
  assertMatch(productionGoNoGoPolicyText, /"requireGithubActionsRunSuccess":\s*true[\s\S]*"requiredGithubWorkflow":\s*"enterprise-infra\.yml"/, "Production go/no-go policy must require a successful remote GitHub Actions workflow run.");
  assertMatch(githubWorkflow, /DR evidence summary[\s\S]*dr-evidence/, "Infra workflow must exercise the DR evidence summary.");
  assertMatch(githubWorkflow, /Off-site restore drill plan[\s\S]*offsite-restore-drill-restic --planOnly/, "Infra workflow must exercise the off-site restore drill plan.");
  assertMatch(githubWorkflow, /Release evidence plan[\s\S]*release-evidence --planOnly/, "Infra workflow must exercise the release evidence command in plan mode.");
  assertMatch(githubWorkflow, /Release artifact gate dry run[\s\S]*release-artifact-gate --envFile \.tmp\/ci-release\.env --sbom \.tmp\/ci-sbom\/pnpm-sbom-ci\.json/, "Infra workflow must exercise the release artifact admission gate.");
  assertMatch(githubWorkflow, /Alert evidence summary[\s\S]*alert-evidence/, "Infra workflow must exercise the alert evidence command in summary mode.");
  assertMatch(githubWorkflow, /Production go-no-go summary[\s\S]*production-go-no-go/, "Infra workflow must exercise the production go/no-go command in summary mode.");
  assertMatch(githubWorkflow, /Pre go-live evidence report[\s\S]*pre-go-live-evidence --infraOnly --repo/, "Infra workflow must exercise the infrastructure-only pre go-live evidence pack.");
  assertMatch(githubWorkflow, /Linux portability check[\s\S]*linux-portability-check/, "Infra workflow must exercise the Linux portability command.");
  assertMatch(githubWorkflow, /Enterprise requirements traceability[\s\S]*enterprise-requirements-check/, "Infra workflow must exercise the enterprise requirements traceability gate.");
  assertMatch(githubWorkflow, /Production readiness checklist[\s\S]*enterprise-requirements-check --manifest governance\/production-readiness\.json/, "Infra workflow must exercise the 20-point production readiness checklist.");
  assertMatch(githubWorkflow, /Production live proof gate rejects missing evidence[\s\S]*--requireLiveProofs[\s\S]*Live proof gate passed without real production evidence/, "Infra workflow must prove the live-production gate rejects missing external evidence.");
  assertMatch(productionReadinessManifest, /"expectedCount":\s*20/, "Production readiness manifest must track the exact 20-point checklist.");
  assertMatch(productionReadinessManifest, /"liveProofCheckRequired":\s*true/, "Production readiness manifest must require mapped live proof checks.");
  assertMatch(productionReadinessManifest, /"liveProofChecks"/, "Production readiness requirements must map to production go/no-go live checks.");
  assertMatch(githubWorkflow, /Repository coverage audit[\s\S]*repo-coverage-check/, "Infra workflow must audit tracked repository coverage.");
  assertMatch(githubWorkflow, /Render staging and backup compose[\s\S]*compose\.waf\.yaml[\s\S]*compose\.staging\.yaml[\s\S]*compose\.backup-scheduler\.yaml/, "Infra workflow must render staging, WAF and backup compose overlays.");
  assertMatch(githubWorkflow, /Secret scan[\s\S]*secret-scan/, "Infra workflow must exercise the secret scanner.");
  assertMatch(githubWorkflow, /HA configuration check[\s\S]*ha-config-check/, "Infra workflow must exercise the HA configuration gate.");
  assertMatch(githubWorkflow, /Managed secrets preflight[\s\S]*managed-secrets-preflight/, "Infra workflow must exercise the managed secrets gate.");
  assertMatch(githubWorkflow, /Secret rotation evidence plan[\s\S]*secret-rotation-evidence/, "Infra workflow must exercise the secret rotation evidence command.");
  assertMatch(githubWorkflow, /DR readiness check[\s\S]*dr-readiness-check/, "Infra workflow must exercise the DR readiness gate.");
  assertMatch(githubWorkflow, /DEPLOY_RUN_PRODUCTION_PREFLIGHT:\s+"1"[\s\S]*DEPLOY_RUN_PRE_GO_LIVE:\s+"1"[\s\S]*DEPLOY_RUN_GO_NO_GO:\s+"1"/, "Production deploy workflow must enforce preflight, pre-go-live evidence and go/no-go.");
  assertMatch(githubWorkflow, /DEPLOY_PRE_GO_LIVE_RESTORE_DRILL:\s+"1"[\s\S]*DEPLOY_PRE_GO_LIVE_OFFSITE_RESTORE_DRY_RUN:\s+"1"/, "Production deploy workflow must require restore and off-site restore evidence.");
  assertMatch(githubWorkflow, /Upload CI evidence reports[\s\S]*actions\/upload-artifact@v4[\s\S]*reports\/[\s\S]*\.tmp\/evidence-bundles\/[\s\S]*retention-days:\s+30/, "Infra workflow must upload non-secret CI evidence reports.");
  assertMatch(githubWorkflow, /permissions:\s*\r?\n\s+contents:\s+read/, "Infra workflow must declare least-privilege read permissions.");
  assertNoMatch(githubWorkflow, /security-events:\s+write|contents:\s+write/, "Infra workflow must not request unused write permissions.");
  assertMatch(githubWorkflow, /compose-and-policy:[\s\S]*timeout-minutes:\s+45[\s\S]*shell-syntax:[\s\S]*timeout-minutes:\s+10[\s\S]*dast-zap:[\s\S]*timeout-minutes:\s+45[\s\S]*deploy-hostinger:[\s\S]*timeout-minutes:\s+90/, "Infra workflow jobs must set explicit timeouts.");
  assertMatch(opsScript, /async function preGoLiveEvidence/, "Ops script must provide a pre go-live evidence command.");
  assertMatch(opsScript, /writeJsonReport\("go-live"[\s\S]*writeMarkdownReport\("go-live"/, "Pre go-live evidence must write JSON and Markdown reports.");
  assertMatch(opsScript, /providerEvidence = \[[\s\S]*Hostinger Ubuntu LTS[\s\S]*Cloudflare DNS\/CDN\/WAF\/Access[\s\S]*providerEvidenceRequired/, "Pre go-live evidence must track remaining provider proof.");
  assertMatch(opsScript, /"pre-go-live-evidence": preGoLiveEvidence/, "Ops command map must expose pre-go-live-evidence.");
  assertMatch(githubWorkflow, /dast-zap:[\s\S]*environment:\s*\r?\n\s+name:\s+staging/, "DAST workflow job must use the staging environment.");
  assertMatch(githubWorkflow, /deploy-hostinger:[\s\S]*environment:\s*\r?\n\s+name:\s+production/, "Hostinger deploy workflow job must use the production environment.");
  assertMatch(githubWorkflow, /deploy-hostinger:[\s\S]*concurrency:[\s\S]*stexor-production-deploy[\s\S]*cancel-in-progress:\s+false/, "Production deploy workflow must serialize deployments.");
  assertMatch(enterprisePlan, /## 1\. HA multi-node production[\s\S]*## 8\. Governance/, "Enterprise 10 plan must cover all eight readiness domains.");
  assertMatch(compose, /image:\s+\$\{BACKEND_BUILD_IMAGE:-stexor\/backend:local\}/, "Local dev backend must run the production image shape, not a generic Node watch container.");
  assertMatch(compose, /image:\s+\$\{WEB_BUILD_IMAGE:-stexor\/web:local\}/, "Local dev web must run the production image shape, not next dev.");
  assertMatch(compose, /image:\s+\$\{WORKER_NOTIFICATIONS_BUILD_IMAGE:-stexor\/worker-notifications:local\}/, "Local dev workers must run production-shaped images.");
  assertNoMatch(compose, /--watch|next dev/, "Local dev compose must not run watch/dev servers.");
  assertNoMatch(compose, /--loader \.\/scripts\/ts-extension-loader\.mjs/, "Dev backend must not use the unsupported Node --loader flag.");
  assertNoMatch(compose, /\.\.\/src:\/workspace/, "Local dev compose must not bind-mount app source into runtime containers.");
  assertNoMatch(compose, /\$\{(?:POSTGRES_PORT|REDIS_PORT|KEYCLOAK_PORT|NATS_CLIENT_PORT|NATS_MONITORING_PORT|MINIO_API_PORT|MINIO_CONSOLE_PORT|BACKEND_PORT|WEB_PORT|PROMETHEUS_PORT|GRAFANA_PORT|LOKI_PORT)/, "Local dev compose must not expose direct service ports; route through Traefik like production.");
  assertMatch(compose, /NODE_ENV:\s+production/, "Local dev app services must run with NODE_ENV=production.");
  assertNoMatch(compose, /\/var\/run\/docker\.sock/, "Compose must not mount docker.sock into application or observability containers.");
  assertNoMatch(promtailConfig, /docker_sd_configs|unix:\/\/\/var\/run\/docker\.sock/, "Promtail must scrape container logs without docker.sock service discovery.");
  assertMatch(promtailConfig, /drop:[\s\S]*older_than:\s+168h/, "Promtail must drop stale Docker log backfill before sending to Loki.");
  assertMatch(promtailConfig, /replace:[\s\S]*authorization[\s\S]*\[REDACTED\]/, "Promtail must apply a sensitive-field redaction pipeline.");
  assertMatch(promtailConfig, /json:[\s\S]*level:\s+level[\s\S]*service:\s+service/, "Promtail must parse structured application log fields.");
  assertMatch(promtailConfig, /labels:[\s\S]*level:[\s\S]*service:/, "Promtail must promote service and level labels for Loki queries.");
  assertMatch(grafanaOverviewDashboard, /Backend errors/, "Grafana dashboard must include backend error log panel.");
  assertMatch(grafanaOverviewDashboard, /Worker errors/, "Grafana dashboard must include worker error log panel.");
  assertMatch(grafanaOverviewDashboard, /WAF events/, "Grafana dashboard must include WAF event log panel.");
  assertMatch(grafanaOverviewDashboard, /Auth failures/, "Grafana dashboard must include auth failure log panel.");
  assertMatch(lokiConfig, /retention_period:\s+168h/, "Loki must enforce bounded log retention.");
  assertMatch(lokiConfig, /reject_old_samples:\s+true/, "Loki must reject stale samples.");
  assertMatch(backendDockerfile, /FROM \$\{NODE_IMAGE\} AS build/, "Backend Dockerfile must use a dedicated JavaScript build stage.");
  assertMatch(backendDockerfile, /pnpm --filter \.\/apps\/backend build/, "Backend Dockerfile must build the production JavaScript bundle.");
  assertMatch(backendDockerfile, /COPY --from=build --chown=node:node \/workspace\/apps\/backend\/dist apps\/backend\/dist/, "Backend runtime image must copy compiled dist from the build stage.");
  assertMatch(backendDockerfile, /CMD \["node", "--enable-source-maps", "dist\/server\.js"\]/, "Backend runtime image must execute compiled JavaScript with source maps.");
  assertNoMatch(backendDockerfile, /register-ts-extension-loader|ts-extension-loader|src\/server\.ts/, "Backend production image must not run TypeScript through a runtime loader.");
  assertMatch(backendDockerfile, /packages\/observability\/package\.json[\s\S]*packages\/observability packages\/observability/, "Backend Dockerfile must include the shared observability package in build and runtime stages.");
  assertMatch(workerDockerfile, /packages\/observability\/package\.json[\s\S]*packages\/observability packages\/observability/, "Worker Dockerfile must include the shared observability package.");
  for (const service of ["traefik", "postgres", "redis", "keycloak", "nats", "minio", "backend", "web", "worker-notifications", "worker-jobs", "prometheus", "node-exporter", "cadvisor", "alertmanager", "grafana", "loki", "promtail"]) {
    assertMatch(
      compose,
      new RegExp(`^\\s{2}${service}:.*?init:\\s+true.*?pids_limit:\\s+\\d+.*?logging:\\s+\\*default_logging`, "ms"),
      `Service ${service} must have init, pids_limit and bounded logging.`,
    );
    assertMatch(
      compose,
      new RegExp(`^\\s{2}${service}:.*?security_opt:\\s*\\r?\\n\\s+- no-new-privileges:true`, "ms"),
      `Service ${service} must set no-new-privileges.`,
    );
  }
  for (const service of ["backend", "web", "worker-notifications", "worker-jobs"]) {
    assertMatch(
      compose,
      new RegExp(`^\\s{2}${service}:.*?read_only:\\s+true.*?no-new-privileges:true.*?cap_drop:\\s*\\r?\\n\\s+- ALL`, "ms"),
      `Dev service ${service} must be read-only, no-new-privileges and cap-drop ALL.`,
    );
  }
  for (const dockerfile of [backendDockerfile, webDockerfile, workerDockerfile]) {
    assertMatch(dockerfile, /^# syntax=docker\/dockerfile:1\.7/m, "Production Dockerfiles must opt into BuildKit cache mount syntax.");
    assertMatch(dockerfile, /--mount=type=cache,target=\/pnpm\/store/, "Production Dockerfiles must cache the pnpm store during dependency install.");
    assertMatch(dockerfile, /COPY --chown=node:node/, "Production Dockerfiles must copy runtime files as the node user.");
    assertMatch(dockerfile, /USER node[\s\S]*RUN[\s\S]*pnpm install/, "Production Dockerfiles must run dependency install as the non-root node user.");
    assertMatch(dockerfile, /^HEALTHCHECK /m, "Production Dockerfiles must include an image-level healthcheck.");
  }
  assertMatch(webDockerfile, /ARG NEXT_PUBLIC_API_URL[\s\S]*NEXT_PUBLIC_ACCOUNT_URL/, "Web Dockerfile must receive public URLs as build args for production bundles.");
  assertMatch(compose, /AUDIT_OUTBOX_ENABLED:\s+\$\{AUDIT_OUTBOX_ENABLED:-true\}/, "Worker jobs must enable audit outbox dispatch by default.");
  assertMatch(compose, /AUDIT_OUTBOX_MAX_ATTEMPTS:\s+\$\{AUDIT_OUTBOX_MAX_ATTEMPTS:-8\}/, "Audit outbox worker must have bounded retry attempts.");
  assertMatch(compose, /alertmanager:[\s\S]*prom\/alertmanager:v0\.32\.2@sha256:/, "Alertmanager must run as a pinned local/prod service.");
  assertMatch(composeProd, /alertmanager:[\s\S]*ports:\s*!reset \[\]/, "Alertmanager must not expose host ports in production.");
  assertMatch(prometheusConfig, /alertmanagers:[\s\S]*alertmanager:9093/, "Prometheus must route alerts to Alertmanager.");
  assertMatch(prometheusConfig, /job_name: alertmanager[\s\S]*alertmanager:9093/, "Prometheus must scrape Alertmanager.");
  assertMatch(prometheusConfig, /job_name: node-exporter[\s\S]*node-exporter:9100/, "Prometheus must scrape node-exporter for host CPU/RAM/disk.");
  assertMatch(prometheusConfig, /job_name: cadvisor[\s\S]*cadvisor:8080/, "Prometheus must scrape cAdvisor for container CPU/RAM.");
  assertMatch(alertmanagerConfig, /worker-notifications:3000\/alerts\/prometheus/, "Alertmanager must deliver alerts to the notification worker.");
  assertMatch(alertmanagerConfig, /authorization:[\s\S]*type:\s+Bearer[\s\S]*credentials_file:\s+\/run\/secrets\/alertmanager_webhook_token/, "Alertmanager webhook delivery must use the shared bearer-token secret.");
  assertMatch(lokiConfig, /alertmanager_url:\s+http:\/\/alertmanager:9093/, "Loki ruler must route alerts to Alertmanager over the Docker network.");
  for (const alertName of ["AuditOutboxDeadLetters", "PostgresBackupStale", "RestoreDrillStale", "AlertmanagerDeliveryFailed", "HostDiskUsageHigh", "HostMemoryUsageHigh", "HostCpuUsageHigh", "ContainerCpuUsageHigh", "ContainerMemoryUsageHigh", "ContainerDisappeared"]) {
    assertMatch(prometheusAlerts, new RegExp(`alert: ${alertName}`), `Prometheus alerts must include ${alertName}.`);
  }
  assertMatch(compose, /node-exporter:[\s\S]*prom\/node-exporter:v1\.10\.2@sha256:/, "Compose must include pinned node-exporter.");
  assertMatch(compose, /cadvisor:[\s\S]*gcr\.io\/cadvisor\/cadvisor:v0\.52\.1@sha256:/, "Compose must include pinned cAdvisor.");
  assertMatch(compose, /loki:[\s\S]*\.\/loki\/rules:\/loki\/rules:ro/, "Loki must mount local alert rules.");
  assertMatch(lokiWafAlerts, /alert: WafBlockSpike[\s\S]*count_over_time/, "Loki rules must alert on anomalous WAF block log volume.");
  assertMatch(workerNotificationsServer, /\/alerts\/prometheus/, "Notification worker must expose an Alertmanager webhook endpoint.");
  assertMatch(workerNotificationsServer, /ALERTMANAGER_WEBHOOK_TOKEN/, "Notification worker must require the Alertmanager webhook token in production.");
  assertMatch(workerNotificationsServer, /notification_alert_webhook_alerts_total/, "Notification worker must expose alert webhook metrics.");
  assertMatch(workerNotificationsServer, /notification_alert_email_deliveries_total/, "Notification worker must expose alert email delivery metrics.");
  assertMatch(workerNotificationsServer, /notification_alert_discord_deliveries_total/, "Notification worker must expose Discord alert delivery metrics.");
  assertMatch(workerNotificationsServer, /notification_alert_telegram_deliveries_total/, "Notification worker must expose Telegram alert delivery metrics.");
  assertMatch(workerNotificationsServer, /ALERT_DISCORD_WEBHOOK_URL/, "Notification worker must support optional Discord alert forwarding through a secret file.");
  assertMatch(workerNotificationsServer, /ALERT_TELEGRAM_BOT_TOKEN/, "Notification worker must support optional Telegram alert forwarding through a secret file.");
  assertMatch(workerJobsServer, /backup_restore_last_success_age_seconds/, "Jobs worker must expose backup/restore freshness metrics.");
  assertMatch(observabilitySource, /FASTIFY_LOG_REDACTION_PATHS[\s\S]*authorization[\s\S]*set-cookie/, "Shared observability package must define sensitive Fastify redaction paths.");
  assertMatch(observabilitySource, /function redactLogValue[\s\S]*isSensitiveLogKey/, "Shared observability package must recursively redact sensitive log fields.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /FASTIFY_LOG_REDACTION_PATHS[\s\S]*LOG_REDACTION_CENSOR/, "Backend must use the shared log redaction policy.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /base:[\s\S]*service:[\s\S]*enterprise-backend/, "Backend logs must include a stable service field.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /formatters:[\s\S]*level\(label\)[\s\S]*return \{ level: label \}/, "Backend log levels must be text labels for Loki queries.");
  assertMatch(workerJobsServer, /createJsonLogger\(serviceName\)/, "Jobs worker must use the shared redacting JSON logger.");
  assertMatch(workerNotificationsServer, /createJsonLogger\(serviceName\)/, "Notifications worker must use the shared redacting JSON logger.");
  assertMatch(backendConfig, /apiDocsEnabled.*isProduction \? "false" : "true"/, "API docs must default off in production.");
  assertMatch(backendConfig, /SESSION_SIGNING_KEYS/, "Session signing key-ring support must be configured.");
  assertMatch(backendConfig, /sensitiveActionFallbackRateLimitMax/, "Sensitive action degraded rate limit budget must be configured.");
  assertMatch(backendConfig, /sessionTouchThrottleMs/, "Session touch throttling must be configurable.");
  assertMatch(readText(path.join(sourceRoot, "apps", "backend", "src", "server.ts")), /skipOnError:\s*false/, "Fastify rate-limit must fail closed instead of skipping on store errors.");
  assertMatch(backendRedisStore, /assertRequestRateAllowed/, "HTTP rate limiting must have a Redis-backed runtime guard.");
  assertMatch(backendRedisStore, /using fail-safe memory window/, "Redis rate-limit degradation must fall back to memory.");
  assertMatch(backendSessionAuth, /shouldPersistSessionTouch/, "Authenticated session touches must be throttled.");
  assertMatch(cryptoRuntime, /readPayloadKeyId/, "Session token verification must support key ids for rotation.");
  assertMatch(opsScript, /async function backupRestoreDrill/, "Ops script must provide an automated backup/restore drill.");
  assertMatch(opsScript, /function writeBackupExecutionReport[\s\S]*writeJsonReport\("backups"[\s\S]*writeMarkdownReport\("backups"/, "Backup commands must write JSON and Markdown execution reports.");
  assertMatch(opsScript, /writeBackupExecutionReport\(\{[\s\S]*engine: "postgres"[\s\S]*engine: "mariadb"[\s\S]*engine: "minio"[\s\S]*engine: "keycloak"[\s\S]*engine: "secret-manager"/, "All backup families must write execution reports.");
  assertMatch(opsScript, /async function backupMinio/, "Ops script must provide MinIO data backups.");
  assertMatch(opsScript, /async function restoreTestMinio/, "Ops script must provide MinIO restore drills.");
  assertMatch(opsScript, /async function backupKeycloakConfig/, "Ops script must provide Keycloak configuration backups.");
  assertMatch(opsScript, /async function restoreTestKeycloakConfig/, "Ops script must provide Keycloak configuration restore dry-runs.");
  assertMatch(opsScript, /async function backupSecretManagerMetadata/, "Ops script must provide Secret Manager metadata backups.");
  assertMatch(opsScript, /async function restoreTestSecretManagerMetadata/, "Ops script must provide Secret Manager metadata restore dry-runs.");
  assertMatch(opsScript, /async function infraHealth/, "Ops script must provide a global infra health gate.");
  assertMatch(opsScript, /admin-traefik-block[\s\S]*admin-prometheus-block[\s\S]*admin-alertmanager-block/, "Infra health must verify unauthenticated internal consoles stay blocked.");
  assertMatch(opsScript, /async function fullRestoreDrill/, "Ops script must provide a full restore drill across all local data families.");
  assertMatch(opsScript, /async function loadBenchmark/, "Ops script must provide 50/100/500 load benchmark reports.");
  assertMatch(opsScript, /function detectEdgeProvider[\s\S]*cf-ray[\s\S]*cloudflare/, "Load benchmark must detect Cloudflare/edge headers.");
  assertMatch(opsScript, /requirePublicTarget[\s\S]*requireEdgeEvidence[\s\S]*target/, "Load benchmark reports must include production target and edge evidence.");
  assertMatch(opsScript, /function writeLoadBenchmarkReport[\s\S]*Status:[\s\S]*payload\.status/, "Load benchmark must write status-bearing reports.");
  assertMatch(opsScript, /catch \(error\)[\s\S]*target-preflight[\s\S]*writeLoadBenchmarkReport/, "Load benchmark must write diagnostic reports for preflight/profile failures.");
  assertMatch(opsScript, /async function rollbackRelease/, "Ops script must provide a controlled release rollback command.");
  assertMatch(opsScript, /"infra-health": infraHealth/, "Ops command map must expose infra-health.");
  assertMatch(opsScript, /"failure-tests": failureTests/, "Ops command map must expose failure-tests.");
  assertMatch(opsScript, /"full-restore-drill": fullRestoreDrill/, "Ops command map must expose full-restore-drill.");
  assertMatch(opsScript, /"load-benchmark": loadBenchmark/, "Ops command map must expose load-benchmark.");
  assertMatch(opsScript, /"rollback-release": rollbackRelease/, "Ops command map must expose rollback-release.");
  assertMatch(opsScript, /function signBackupArtifact/, "Ops script must sign PostgreSQL backup artifacts.");
  assertMatch(opsScript, /function verifyBackupArtifact/, "Ops script must verify PostgreSQL backup signatures before restore.");
  assertMatch(opsScript, /verifyBackupArtifact\(backupFile\)/, "Restore paths must verify signed backup artifacts before pg_restore.");
  assertMatch(opsScript, /Missing local backup artifacts for off-site upload/, "Restic off-site upload must require all backup artifact families by default.");
  assertMatch(opsScript, /async function offsiteRestoreDrillRestic/, "Ops script must provide an off-site Restic restore drill.");
  assertMatch(opsScript, /resticPassthroughEnvKeys[\s\S]*AWS_ACCESS_KEY_ID[\s\S]*AWS_SECRET_ACCESS_KEY/, "Restic operations must pass S3-compatible credentials into the Restic container.");
  assertMatch(opsScript, /"snapshots",\s*"--json",\s*"--tag",\s*tag/, "Off-site restore drill must validate the remote Restic snapshot list by tag.");
  assertMatch(opsScript, /function classifyResticRepository[\s\S]*repositoryOffsite/, "Off-site restore evidence must classify remote Restic repositories.");
  assertMatch(opsScript, /"restore",\s*"--target",\s*"\/restore",\s*"--dry-run",\s*"--verbose=2"/, "Off-site restore drill must support a non-writing Restic restore dry-run.");
  assertMatch(opsScript, /function offsiteRestoreCoverage[\s\S]*missingRequiredFamilies[\s\S]*infraHealthOk/, "Off-site restore drill must compute full data-family coverage.");
  assertMatch(opsScript, /discoverRestoredBackupArtifacts[\s\S]*stageRestoredBackupArtifact[\s\S]*verifyBackupArtifact/, "Off-site restore drill must stage and verify restored signed artifacts before tests.");
  assertMatch(opsScript, /restoreTestPostgres[\s\S]*restoreTestMariadb[\s\S]*restoreTestMinio[\s\S]*restoreTestKeycloakConfig[\s\S]*restoreTestSecretManagerMetadata/, "Off-site restore drill must reuse every data-family restore test.");
  assertMatch(opsScript, /writeJsonReport\("offsite-restore-drills"[\s\S]*writeMarkdownReport\("offsite-restore-drills"/, "Off-site restore drill must write JSON and Markdown evidence reports.");
  assertMatch(opsScript, /"offsite-restore-drill-restic": offsiteRestoreDrillRestic/, "Ops command map must expose offsite-restore-drill-restic.");
  assertMatch(opsScript, /await backupRestoreDrill\(\)/, "Enterprise hardening audit must execute a backup/restore drill.");
  assertMatch(opsScript, /await backupRestoreDrillMariadb\(\)/, "Enterprise hardening audit must execute a MariaDB backup/restore drill.");
  assertMatch(opsScript, /await backupRestoreDrillMinio\(\)/, "Enterprise hardening audit must execute a MinIO backup/restore drill.");
  assertMatch(opsScript, /await backupRestoreDrillKeycloakConfig\(\)/, "Enterprise hardening audit must execute a Keycloak config backup/restore drill.");
  assertMatch(opsScript, /await backupRestoreDrillSecretManagerMetadata\(\)/, "Enterprise hardening audit must execute a Secret Manager metadata backup/restore drill.");
  assertMatch(opsScript, /async function prunePostgresBackups/, "Ops script must provide backup artifact retention cleanup.");
  assertMatch(opsScript, /await prunePostgresBackups\(\{ dryRun: true \}\)/, "Enterprise hardening audit must dry-run backup artifact retention.");
  assertMatch(opsScript, /backup-restore-drill\.sh.*restore-drill\.log/s, "PostgreSQL cron installer must schedule restore drills.");
  assertMatch(opsScript, /prune-postgres-backups\.sh.*retention\.log/s, "PostgreSQL cron installer must schedule backup retention cleanup.");
  assertMatch(offsiteCronScript, /backup-minio\.sh.*minio-backup\.log/s, "Off-site cron installer must schedule MinIO backups.");
  assertMatch(offsiteCronScript, /backup-keycloak\.sh.*keycloak-backup\.log/s, "Off-site cron installer must schedule Keycloak backups.");
  assertMatch(offsiteCronScript, /backup-secret-manager-metadata\.sh.*secret-manager-backup\.log/s, "Off-site cron installer must schedule Secret Manager metadata backups.");
  assertMatch(backupMinioWrapper, /backup-minio/, "MinIO backup wrapper must delegate to stexor-ops.");
  assertMatch(backupKeycloakWrapper, /backup-keycloak/, "Keycloak backup wrapper must delegate to stexor-ops.");
  assertMatch(backupSecretManagerWrapper, /backup-secret-manager-metadata/, "Secret Manager backup wrapper must delegate to stexor-ops.");
  assertMatch(alertEvidenceWrapper, /alert-evidence/, "Alert evidence wrapper must delegate to stexor-ops.");
  assertMatch(offsiteRestoreDrillWrapper, /offsite-restore-drill-restic/, "Off-site restore drill wrapper must delegate to stexor-ops.");
  assertMatch(infraHealthWrapper, /infra-health/, "Infra health wrapper must delegate to stexor-ops.");
  assertMatch(failureTestsWrapper, /failure-tests/, "Failure-tests wrapper must delegate to stexor-ops.");
  assertMatch(drEvidenceWrapper, /dr-evidence/, "DR evidence wrapper must delegate to stexor-ops.");
  assertMatch(fullRestoreDrillWrapper, /full-restore-drill/, "Full restore drill wrapper must delegate to stexor-ops.");
  assertMatch(loadBenchmarkWrapper, /load-benchmark/, "Load benchmark wrapper must delegate to stexor-ops.");
  assertMatch(linuxPortabilityWrapper, /linux-portability-check/, "Linux portability wrapper must delegate to stexor-ops.");
  assertMatch(rollbackReleaseWrapper, /rollback-release/, "Rollback wrapper must delegate to stexor-ops.");
  assertMatch(releaseEvidenceWrapper, /release-evidence/, "Release evidence wrapper must delegate to stexor-ops.");
  assertMatch(releaseArtifactGateWrapper, /release-artifact-gate/, "Release artifact gate wrapper must delegate to stexor-ops.");
  assertMatch(productionGoNoGoWrapper, /production-go-no-go/, "Production go/no-go wrapper must delegate to stexor-ops.");
  assertMatch(opsScript, /async function productionGoNoGo/, "Ops script must provide a production go/no-go evidence gate.");
  assertMatch(opsScript, /writeJsonReport\("go-no-go"[\s\S]*writeMarkdownReport\("go-no-go"/, "Production go/no-go must write JSON and Markdown reports.");
  assertMatch(opsScript, /latestJsonReport\("vps-bootstrap", "vps-bootstrap-apply-", \(payload\) => \([\s\S]*payload\.mode === "apply" && payload\.status === "applied"/, "Production go/no-go must require a VPS bootstrap apply report.");
  assertMatch(opsScript, /latestJsonReport\("vps-hardening", "vps-hardening-apply-", \(payload\) => \{[\s\S]*dockerDaemonApplied[\s\S]*sshReloadApplied[\s\S]*payload\.mode === "apply" && payload\.status === "applied" && dockerDaemonApplied && sshReloadApplied/, "Production go/no-go must require a VPS hardening apply report with SSH reload and Docker daemon hardening.");
  assertMatch(opsScript, /latestJsonReport\("vps-host", "vps-host-readiness-", \(payload\) => \([\s\S]*productionEvidence !== false[\s\S]*payload\.mode !== "diagnostic"/, "Production go/no-go must ignore diagnostic VPS host readiness reports.");
  assertMatch(opsScript, /vpsExpectedSshPort[\s\S]*vpsHasSshPortEvidence[\s\S]*ssh-port-expected[\s\S]*ufw-ssh-port-allowed[\s\S]*sshPortEvidence/, "Production go/no-go must require VPS readiness evidence for the hardened SSH port and UFW allow rule.");
  assertMatch(opsScript, /latestJsonReport\("vps-host"[\s\S]*latestJsonReport\("cloudflare-access"/, "Production go/no-go must evaluate VPS and Cloudflare Access live reports.");
  assertMatch(opsScript, /latestRestoreOffsite === true/, "Production go/no-go must require Restic restore evidence from a remote off-site repository.");
  assertMatch(opsScript, /latestRestoreCoverage\?\.complete === true/, "Production go/no-go must require full off-site restore family coverage.");
  assertMatch(opsScript, /"production-go-no-go": productionGoNoGo/, "Ops command map must expose production-go-no-go.");
  assertMatch(opsScript, /async function linuxPortabilityCheck/, "Ops script must provide a Linux portability check.");
  assertMatch(opsScript, /scanPortabilityFiles[\s\S]*utf8-bom[\s\S]*crlf[\s\S]*windows-path[\s\S]*powershell-dependency/, "Linux portability check must scan BOM, CRLF, Windows paths and PowerShell dependencies.");
  assertMatch(opsScript, /writeJsonReport\("linux-portability"[\s\S]*writeMarkdownReport\("linux-portability"/, "Linux portability check must write JSON and Markdown reports.");
  assertMatch(opsScript, /await linuxPortabilityCheck\(\)/, "Enterprise 10 readiness gate must include Linux portability.");
  assertMatch(opsScript, /confirmServiceStop/, "Failure tests must require an explicit flag before stopping containers.");
  assertMatch(opsScript, /confirmRollback/, "Rollback command must require an explicit flag before changing runtime state.");
  assertMatch(opsScript, /dockerStatsSnapshot/, "Load benchmark must capture Docker CPU/RAM snapshots.");
  assertMatch(opsScript, /loadEdgeEvidence[\s\S]*requireLoadEdgeEvidence/, "Production go/no-go must require load benchmark edge evidence.");
  assertMatch(sourcePackage, /"deps:sbom":\s+"node scripts\/run-infra-ops\.mjs generate-sbom"/, "Application package must expose containerized pnpm deps:sbom.");
  assertMatch(sourcePackage, /"enterprise:10-check":\s+"node scripts\/run-infra-ops\.mjs enterprise-10-check"/, "Application package must expose containerized pnpm enterprise:10-check.");
  assertMatch(sourcePackage, /"infra:health":\s+"node scripts\/run-infra-ops\.mjs infra-health"/, "Application package must expose containerized pnpm infra:health.");
  assertMatch(sourcePackage, /"infra:release-gate":\s+"node scripts\/run-infra-ops\.mjs release-artifact-gate"/, "Application package must expose containerized pnpm infra:release-gate.");
  assertNoMatch(sourcePackage, /\.\.\/stexor-platform-infrastructure\/scripts\/stexor-ops\.mjs/, "Application package scripts must not call infrastructure ops through host Node.");
  assertMatch(sourceInfraOpsLauncher, /stexor\/ops:local/, "Application infra ops launcher must use the Dockerized ops image.");
  assertMatch(sourceInfraOpsLauncher, /dockerArgs = \[[\s\S]*"run"[\s\S]*dockerArgs\.push\(opsImage/, "Application infra ops launcher must execute docker run with the ops image.");
  assertMatch(sourceInfraOpsLauncher, /"docker",\s+"ops\.Dockerfile"/, "Application infra ops launcher must build the ops image when needed.");
  assertMatch(sourceInfraOpsLauncher, /STEXOR_SOURCE_ROOT=\/src_stexor/, "Application infra ops launcher must map source into the ops container.");
  assertMatch(sourceInfraOpsLauncher, /STEXOR_OPS_NETWORK[\s\S]*dockerArgs\.push\("--network", opsNetwork\)/, "Application infra ops launcher must use host networking by default for local routed domains.");
  assertNoMatch(sourceInfraOpsLauncher, /stexor-ops\.mjs/, "Application infra ops launcher must not execute the infra runner directly on the host.");
  assertMatch(infraRenovate, /dependencyDashboardApproval/, "Infra repo must require approval for major dependency updates.");
  assertMatch(sourceRenovate, /dependencyDashboardApproval/, "Application repo must require approval for major dependency updates.");
  assertMatch(infraRenovate, /"docker-compose"/, "Infra Renovate config must track compose images.");
  assertMatch(sourceRenovate, /"npm"/, "Application Renovate config must track npm dependencies.");
  assertMatch(infraGitattributes, /^\* text=auto eol=lf/m, "Infra repo must normalize text files to LF for Ubuntu VPS.");
  assertMatch(sourceGitattributes, /^\* text=auto eol=lf/m, "Application repo must normalize text files to LF for Ubuntu VPS.");
  assertMatch(opsScript, /async function supplyChainHygiene/, "Ops script must provide a mandatory supply-chain gate.");
  assertMatch(opsScript, /await supplyChainHygiene\(\)/, "Enterprise hardening audit must execute the supply-chain gate.");
  assertMatch(opsScript, /async function faultInjectionTests/, "Ops script must provide fault-injection tests.");
  assertMatch(opsScript, /await faultInjectionTests\(\)/, "Enterprise hardening audit must execute fault-injection tests.");
  assertMatch(opsScript, /statement_timeout = '1ms'[\s\S]*pg_sleep/, "Fault-injection tests must exercise live PostgreSQL statement timeout.");
  assertMatch(opsScript, /async function loadProfile/, "Ops script must provide a sustained load profile command.");
  assertMatch(opsScript, /async function haConfigCheck/, "Ops script must provide an HA readiness gate.");
  assertMatch(opsScript, /async function managedSecretsPreflight/, "Ops script must provide a managed-secrets preflight.");
  assertMatch(opsScript, /async function releaseArtifactGate/, "Ops script must provide a release artifact admission gate.");
  assertMatch(opsScript, /async function alertEvidence/, "Ops script must provide an alert evidence command.");
  assertMatch(opsScript, /writeJsonReport\("alerts"[\s\S]*writeMarkdownReport\("alerts"/, "Alert evidence must write JSON and Markdown reports.");
  assertMatch(opsScript, /"alert-evidence": alertEvidence/, "Ops command map must expose alert-evidence.");
  assertMatch(opsScript, /await collectEvidenceStep\(steps, \{ name: "alert-evidence-summary"/, "Pre go-live evidence must include an alert evidence summary.");
  assertMatch(opsScript, /async function releaseEvidence/, "Ops script must provide a release evidence pack command.");
  assertMatch(opsScript, /writeJsonReport\("release"[\s\S]*writeMarkdownReport\("release"/, "Release evidence must write JSON and Markdown reports.");
  assertMatch(opsScript, /function writeReleaseEvidenceReport[\s\S]*Status:[\s\S]*payload\.status/, "Release evidence must write status-bearing reports.");
  assertMatch(opsScript, /catch \(error\)[\s\S]*issues\.push[\s\S]*writeReleaseEvidenceReport/, "Release evidence must write diagnostic reports for validation failures.");
  assertMatch(opsScript, /release\/previous-images\.json/, "Release evidence must write the rollback target manifest.");
  assertMatch(opsScript, /writeRollbackPlanReport\([\s\S]*rollbackDryRun[\s\S]*dryRun/, "Release evidence must link a validated rollback dry-run report.");
  assertMatch(opsScript, /releaseRollbackOk[\s\S]*rollback\?\.dryRun\?\.validated === true/, "Production go/no-go must require a validated rollback dry-run.");
  assertMatch(opsScript, /latestJsonReport\("release", "release-evidence-", \(payload\) => payload\.mode === "evidence"\)/, "Production go/no-go must ignore release plan reports.");
  assertMatch(opsScript, /releasePayload\.status === "passed"/, "Production go/no-go must require passed release evidence.");
  assertMatch(opsScript, /function validateSlsaProvenance[\s\S]*https:\/\/slsa\.dev\/provenance\/v1[\s\S]*predicate\.buildDefinition\.buildType/, "Release evidence must validate SLSA v1 provenance structure.");
  assertMatch(opsScript, /slsaProvenance\?\.status === "passed"/, "Production go/no-go must require validated SLSA provenance.");
  assertMatch(opsScript, /"release-evidence": releaseEvidence/, "Ops command map must expose release-evidence.");
  assertMatch(opsScript, /await collectEvidenceStep\(steps, \{ name: "release-evidence-plan"/, "Pre go-live evidence must include a release evidence plan.");
  assertMatch(opsScript, /async function drReadinessCheck/, "Ops script must provide a DR/PITR readiness gate.");
  assertMatch(opsScript, /async function drEvidence/, "Ops script must provide a DR evidence summary command.");
  assertMatch(opsScript, /writeJsonReport\("dr"[\s\S]*writeMarkdownReport\("dr"/, "DR evidence must write JSON and Markdown reports.");
  assertMatch(opsScript, /Average full restore[\s\S]*P95 full restore/, "DR evidence must document average and P95 restore timing.");
  assertMatch(opsScript, /"dr-evidence": drEvidence/, "Ops command map must expose dr-evidence.");
  assertMatch(opsScript, /await collectEvidenceStep\(steps, \{ name: "dr-evidence-summary"/, "Pre go-live evidence must include a DR evidence summary.");
  assertMatch(opsScript, /async function securityMatrix/, "Ops script must provide a security test matrix gate.");
  assertMatch(opsScript, /async function chaosProfile/, "Ops script must provide an opt-in chaos profile.");
  assertMatch(opsScript, /async function governanceCheck/, "Ops script must provide a governance gate.");
  assertMatch(opsScript, /async function repoCoverageCheck/, "Ops script must provide a repository coverage audit gate.");
  assertMatch(opsScript, /enterpriseRequirementLiveProofResult[\s\S]*requireLiveProofs[\s\S]*liveProofIssues/, "Enterprise requirement reports must optionally enforce live production proof separately from repo evidence.");
  assertMatch(opsScript, /repoStatus:\s+repoIssues\.length \? "failed" : "passed"[\s\S]*liveProofStatus/, "Enterprise requirement reports must keep repository evidence status separate from live proof status.");
  assertMatch(opsScript, /async function enterpriseTenCheck/, "Ops script must provide the combined enterprise 10 readiness gate.");
  assertMatch(opsScript, /await externalUptimeCheck\(\{ dryRun: true \}\)/, "Enterprise 10 readiness gate must validate the external uptime manifest.");
  assertMatch(opsScript, /"external-uptime-check": externalUptimeCheck/, "Ops command map must expose external-uptime-check.");
  assertMatch(opsScript, /requireProviderEvidence[\s\S]*providerEvidencePath/, "External uptime command must support required provider evidence.");
  assertMatch(opsScript, /latestJsonReport\("uptime", "external-uptime-", \(payload\) => \([\s\S]*providerEvidence\?\.verified === true/, "Production go/no-go must ignore uptime reports without provider evidence.");
  assertMatch(opsScript, /latestJsonReport\("load", "load-benchmark-", \(payload\) => \{[\s\S]*providerMatched === true/, "Production go/no-go must ignore non-public load reports when edge evidence is required.");
  assertMatch(opsScript, /load\.payload\.status === "passed"/, "Production go/no-go must require a passed load benchmark report.");
  assertMatch(opsScript, /latestJsonReport\("cloudflare-access", "cloudflare-access-admin-", \(payload\) => \([\s\S]*payload\.mode === "verifyRemote"/, "Production go/no-go must ignore Cloudflare Access plan reports.");
  assertMatch(opsScript, /function goNoGoRemediation[\s\S]*vps-bootstrap-ubuntu\.sh --apply[\s\S]*vps-hardening-ubuntu\.sh --apply[\s\S]*Remediation Checklist[\s\S]*remediation/, "Production go/no-go must include an actionable remediation checklist in JSON and Markdown.");
  assertMatch(opsScript, /Promise\.all\(Array\.from\(\{ length: workerCount \}/, "Load probes must issue real concurrent requests.");
  assertMatch(opsScript, /\/stexor-platform-infrastructure:ro/, "Disposable Linux source checks must mount infrastructure read-only for cross-repo hygiene gates.");
  assertMatch(sourcePackage, /"deps:supply-chain":\s+"node scripts\/supply-chain-gate\.mjs"/, "Root package must expose the supply-chain gate.");
  assertMatch(sourceSupplyChainGate, /"audit",\s+"--prod",\s+"--audit-level"/, "Supply-chain gate must run a production CVE audit.");
  assertMatch(sourceSupplyChainGate, /CycloneDX/, "Supply-chain gate must generate a CycloneDX SBOM.");
  assertMatch(sourceSupplyChainGate, /Denied or unknown production dependency licenses/, "Supply-chain gate must enforce a license policy.");
  assertMatch(sourceCiWorkflow, /pnpm deps:supply-chain/, "Enterprise CI must run the mandatory supply-chain gate.");
  assertMatch(sourceCiWorkflow, /pnpm-cyclonedx-sbom/, "Enterprise CI must upload the generated CycloneDX SBOM artifact.");
  assertMatch(sourceCiWorkflow, /Source hygiene guard[\s\S]*shell:\s+bash/, "Application CI source hygiene guard must run in bash.");
  assertMatch(sourceCiWorkflow, /sh "\$INFRA\/scripts\/stexor-ops\.sh" static-security-check/, "Application CI must call infrastructure gates through the Dockerized ops wrapper.");
  assertNoMatch(sourceCiWorkflow, /shell:\s+pwsh|static-security-check\.ps1|node "\$INFRA\/scripts\/stexor-ops\.mjs"/, "Application CI must not depend on PowerShell or direct host Node infra gates.");
  assertNoMatch(`${sourceDocs}\n${sourceTopLevelDocs}`, /node\s+(?:\.\.\/stexor-platform-infrastructure\/scripts\/)?scripts\/stexor-ops\.mjs|node\s+\.\.\/stexor-platform-infrastructure\/scripts\/stexor-ops\.mjs/, "Application operator docs must point to the Dockerized ops wrapper.");
  assertMatch(opsScript, /operation = 'restore_test'[\s\S]*status = 'success'/, "Runtime checks must require a recorded successful restore_test run.");
  assertMatch(workerJobsServer, /AuditOutboxDispatcher/, "Worker jobs must run the durable audit outbox dispatcher.");
  assertMatch(workerJobsServer, /audit_outbox_rows/, "Worker jobs metrics must expose audit outbox lifecycle gauges.");
  assertMatch(workerJobsAuditOutboxStore, /for update skip locked/i, "Audit outbox dispatcher must use transaction-safe row claims.");
  assertMatch(workerJobsAuditOutboxStore, /status = 'dead'/, "Audit outbox dispatcher must support a dead-letter terminal state.");
  assertMatch(workerJobsNatsSink, /Idempotency-Key/, "Audit outbox delivery must publish an idempotency key.");
  assertNoMatch(webNextConfig, /Content-Security-Policy/, "Web CSP must be nonce-based middleware, not a static header.");
  if (fs.existsSync(path.join(sourceRoot, "apps", "web", "src", "middleware.ts"))) {
    fail("Web must use src/proxy.ts instead of src/middleware.ts.");
  }
  assertMatch(webProxy, /export function proxy/, "Web CSP proxy must export the Next.js proxy handler.");
  assertMatch(webProxy, /'nonce-\$\{nonce\}'/, "Web CSP must include a request nonce.");
  assertNoMatch(webProxy, /script-src[^\n`"]*unsafe-inline/, "Web script CSP must not allow unsafe-inline.");
  assertNoMatch(webProxy, /style-src[^\n`"]*unsafe-inline/, "Web style CSP must not allow unsafe-inline.");
  assertMatch(webProxy, /style-src-elem 'self' 'nonce-\$\{nonce\}'/, "Web CSP must nonce stylesheet elements.");
  assertMatch(webProxy, /style-src-attr 'none'/, "Web CSP must block style attributes.");
  assertNoMatch(browserUiSource, /style=\{/, "Browser UI source must not use React inline style props.");
  assertNoMatch(browserUiSource, /dangerouslySetInnerHTML/, "Browser UI source must not inject inline style/script blocks.");
  assertNoMatch(browserUiSource, /import\s*\{[^}]*\bmotion\b[^}]*\}\s*from\s*["']framer-motion["']/, "Browser UI source must not import Framer Motion DOM components because they write inline style attributes at runtime.");
  assertNoMatch(browserUiSource, /import\s+\*\s+as\s+motion\s+from\s*["']framer-motion["']/, "Browser UI source must not import Framer Motion DOM components because they write inline style attributes at runtime.");
  assertMatch(browserUiSource, /createDynamicCssRule/, "CSP-safe motion and scroll affordances must write dynamic geometry through stylesheet rules.");
  assertNoMatch(webSource, /container\.style\./, "Bot-protection widgets must not position themselves with CSP-blocked style attributes.");
  assertMatch(webSource, /sx-account-turnstile-container/, "Turnstile must use account-owned static CSS instead of inline styles.");
  for (const fallback of [webAppNotFound, webGlobalError]) {
    assertMatch(fallback, /SectionCard[\s\S]*className="ui-section"/, "Web fallback error surfaces must use CSP-safe UI package styles instead of Next inline styled defaults.");
  }
  assertNoMatch(webRememberModel, /JSON\.stringify\(accounts/, "Remembered accounts must not persist full profile objects in localStorage.");

  const rlsSql = readText(path.join(infraRoot, "postgres", "migrations", "005_row_level_security_hardening.sql"));
  const auditOutboxSql = readText(path.join(infraRoot, "postgres", "migrations", "007_durable_audit_outbox.sql"));
  const auditUnlinkSql = readText(path.join(infraRoot, "postgres", "migrations", "008_audit_account_unlink.sql"));
  const auditOutboxDispatcherSql = readText(path.join(infraRoot, "postgres", "migrations", "009_audit_outbox_dispatcher.sql"));
  assertMatch(rlsSql, /FORCE ROW LEVEL SECURITY/, "RLS hardening migration must force row-level security.");
  assertMatch(auditOutboxSql, /CREATE TABLE IF NOT EXISTS stexor_account\.audit_outbox/, "Audit outbox migration must create a durable queue.");
  assertMatch(auditOutboxSql, /FORCE ROW LEVEL SECURITY/, "Audit outbox must force row-level security.");
  assertMatch(auditUnlinkSql, /NEW\.account_id IS NULL/, "Audit append-only trigger must permit account_id unlink for cleanup/anonymization.");
  assertMatch(auditOutboxDispatcherSql, /'dead'/, "Audit outbox dispatcher migration must add dead-letter status.");
  assertMatch(auditOutboxDispatcherSql, /idx_audit_outbox_due_dispatch/, "Audit outbox dispatcher migration must add a due-dispatch index.");
  log("Static security checks passed.");
}

async function validateLocalSecrets() {
  const secretsDir = path.resolve(argv.secretsDir ?? path.join(infraRoot, "secrets"));
  const required = [
    "postgres_superuser_password",
    "app_db_password",
    "keycloak_db_password",
    "redis_password",
    "keycloak_admin_password",
    "nats_password",
    "minio_root_password",
    "mariadb_root_password",
    "phpmyadmin_control_password",
    "grafana_admin_password",
    "session_secret",
    "session_signing_keys",
    "projects_gateway_signing_keys",
    "hash_pepper_keys",
    "backup_signing_keys",
    "smtp_password",
    "google_recaptcha_secret_key",
    "cloudflare_turnstile_secret_key",
    "google_oauth_client_secret",
    "database_url",
    "nats_url",
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
  for (const name of ["session_signing_keys", "projects_gateway_signing_keys", "hash_pepper_keys", "backup_signing_keys"]) {
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

async function accountIntegrationTests() {
  const apiBase = argv.apiBase ?? "https://api.localhost.com";
  log("==> Account integration tests");
  const signingKey = backendSessionSigningKey();

  const stamp = Date.now();
  const email = `integration+${stamp}@stexor.local`;
  const username = `integration_${stamp}`;
  const code = "184729";
  const signupChallengeId = `it_signup_${stamp}`;
  const loginChallengeId = `it_login_${stamp}`;
  const secondSignupChallengeId = `it_signup_second_${stamp}`;
  const redisPrefix = "stexor";
  let accountId = null;
  const createdAccountIds = [];

  try {
    const expiresAt = Date.now() + 8 * 60 * 1000;
    redisSetValue(`${redisPrefix}:otp:${signupChallengeId}`, JSON.stringify({
      id: signupChallengeId,
      purpose: "signup",
      destination: email,
      codeHash: backendSecretHash(code),
      expiresAt,
      attempts: 0,
    }), 480000);
    redisSetPlainValue(`${redisPrefix}:otp-verified:${signupChallengeId}`, "1", 480000);

    const register = await request("POST", `${apiBase}/account/bootstrap/register`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: {
        firstName: "Integration",
        lastName: "Test",
        email,
        username,
        dateOfBirth: "1990-01-01",
        challengeId: signupChallengeId,
        code,
      },
    });
    assertStatus(register, 200, "signup/register");
    accountId = register.json?.profile?.id;
    if (!accountId) {
      fail("signup/register did not return profile id.");
    }
    createdAccountIds.push(accountId);

    const sessionId = postgresOut("enterprise-postgres", "stexor_app", "postgres", `select s.id::text from stexor_account.sessions s join stexor_account.accounts a on a.id = s.account_id where a.external_id = ${sqlString(accountId)} and s.status = 'active' order by s.current_session desc, s.last_seen_at desc limit 1;`).trim();
    if (!sessionId) {
      fail("No active session created for integration account.");
    }
    const cookie = newSignedCookie(signingKey, accountId, sessionId);
    const authHeaders = { Cookie: cookie, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" };

    assertStatus(await request("GET", `${apiBase}/account/snapshot`, { headers: authHeaders }), 200, "snapshot");
    const accountsResponse = await request("GET", `${apiBase}/auth/accounts`, { headers: authHeaders });
    assertStatus(accountsResponse, 200, "account switcher accounts");
    const accountSwitchCookie = cookieFromHeaders(accountsResponse.headers, "stexor_account_switcher");
    if (!accountSwitchCookie) {
      fail("auth/accounts did not refresh account switch cookie.");
    }
    assertStatus(await request("POST", `${apiBase}/auth/switch-account`, {
      headers: { Cookie: `${cookie}; ${accountSwitchCookie}`, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" },
      body: { accountId },
    }), 200, "switch account");

    const profileBody = {
      username,
      firstName: "Integration",
      lastName: "Verified",
      email,
      dateOfBirth: "1990-01-01",
      language: "it-IT",
      country: "IT",
      avatarImage: null,
    };
    assertStatus(await request("PATCH", `${apiBase}/account/profile`, {
      headers: { Cookie: cookie, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "cross-site", "x-stexor-csrf": "1" },
      body: profileBody,
    }), 200, "trusted cross-site profile patch");
    assertStatus(await request("PATCH", `${apiBase}/account/profile`, {
      headers: { Cookie: cookie, Origin: "https://evil.example", "Sec-Fetch-Site": "cross-site", "x-stexor-csrf": "1" },
      body: { ...profileBody, firstName: "Blocked" },
    }), 403, "untrusted cross-site profile patch");

    const credentialId = crypto.randomBytes(16).toString("base64url");
    postgres("enterprise-postgres", "stexor_app", "postgres", `insert into stexor_account.passkeys (account_id, credential_id, public_key, counter, label, device_type, backed_up, transports) select id, ${sqlString(credentialId)}, decode(repeat('ab',32),'hex'), 0, 'Integration passkey', 'singleDevice', false, ARRAY['internal']::text[] from stexor_account.accounts where external_id = ${sqlString(accountId)} on conflict (credential_id) do nothing;`);
    const passkeyOptions = await request("POST", `${apiBase}/auth/login/passkey/options`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { email },
    });
    assertStatus(passkeyOptions, 200, "passkey login options");
    if (!passkeyOptions.json?.allowCredentials?.length) {
      fail("passkey login options did not include seeded passkey.");
    }

    const secondEmail = `integration.second+${stamp}@stexor.local`;
    const secondUsername = `int2_${stamp.toString(36)}`;
    redisSetValue(`${redisPrefix}:otp:${secondSignupChallengeId}`, JSON.stringify({
      id: secondSignupChallengeId,
      purpose: "signup",
      destination: secondEmail,
      codeHash: backendSecretHash(code),
      expiresAt,
      attempts: 0,
    }), 480000);
    redisSetPlainValue(`${redisPrefix}:otp-verified:${secondSignupChallengeId}`, "1", 480000);
    const secondRegister = await request("POST", `${apiBase}/account/bootstrap/register`, {
      headers: { Cookie: `${cookie}; ${accountSwitchCookie}`, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" },
      body: {
        firstName: "Integration",
        lastName: "Second",
        email: secondEmail,
        username: secondUsername,
        dateOfBirth: "1991-01-01",
        challengeId: secondSignupChallengeId,
        code,
      },
    });
    assertStatus(secondRegister, 200, "signup/register while another account is logged in");
    const secondAccountId = secondRegister.json?.profile?.id;
    if (!secondAccountId) {
      fail("second signup/register did not return profile id.");
    }
    createdAccountIds.push(secondAccountId);
    const secondCredentialId = crypto.randomBytes(16).toString("base64url");
    postgres("enterprise-postgres", "stexor_app", "postgres", `insert into stexor_account.passkeys (account_id, credential_id, public_key, counter, label, device_type, backed_up, transports) select id, ${sqlString(secondCredentialId)}, decode(repeat('cd',32),'hex'), 0, 'Integration second passkey', 'singleDevice', false, ARRAY['internal']::text[] from stexor_account.accounts where external_id = ${sqlString(secondAccountId)} on conflict (credential_id) do nothing;`);
    const crossAccountPasskeyOptions = await request("POST", `${apiBase}/auth/login/passkey/options`, {
      headers: { Cookie: cookie, Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site", "x-stexor-csrf": "1" },
      body: { email: secondEmail },
    });
    assertStatus(crossAccountPasskeyOptions, 200, "passkey login options for added account while current account cookie exists");
    const crossAccountCredentialIds = (crossAccountPasskeyOptions.json?.allowCredentials ?? []).map((credential) => credential.id);
    if (!crossAccountCredentialIds.includes(secondCredentialId) || crossAccountCredentialIds.includes(credentialId)) {
      fail("passkey login options for added account resolved the current account instead of the requested account.");
    }

    redisSetValue(`${redisPrefix}:otp:${loginChallengeId}`, JSON.stringify({
      id: loginChallengeId,
      purpose: "login",
      destination: email,
      codeHash: backendSecretHash(code),
      expiresAt,
      attempts: 0,
    }), 480000);
    assertStatus(await request("POST", `${apiBase}/account/bootstrap/email-otp/verify`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { challengeId: loginChallengeId, code, email },
    }), 200, "email OTP login verify");

    const backupRotate = await request("POST", `${apiBase}/account/backup-codes/rotate`, { headers: authHeaders });
    assertStatus(backupRotate, 200, "backup code rotate");
    const backupCode = backupRotate.json?.codes?.[0];
    const recoveryBackupCode = backupRotate.json?.codes?.[1];
    assertStatus(await request("POST", `${apiBase}/account/backup-codes/verify`, {
      headers: authHeaders,
      body: { code: backupCode },
    }), 200, "backup code verify");
    assertStatus(await request("POST", `${apiBase}/account/backup-codes/verify`, {
      headers: authHeaders,
      body: { code: backupCode },
    }), 400, "backup code one-time reuse block");
    assertStatus(await request("POST", `${apiBase}/auth/login/recovery/verify`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { email, method: "backup_code", code: recoveryBackupCode },
    }), 200, "backup code recovery login verify");
    assertStatus(await request("POST", `${apiBase}/auth/login/recovery/verify`, {
      headers: { Origin: "https://account.localhost.com", "Sec-Fetch-Site": "same-site" },
      body: { email, method: "backup_code", code: recoveryBackupCode },
    }), 400, "backup code recovery one-time reuse block");

    const extraSessionId = crypto.randomUUID();
    postgres("enterprise-postgres", "stexor_app", "postgres", `insert into stexor_account.sessions (id, account_id, device, browser, trusted, current_session, auth_method, status, created_at, last_seen_at, expires_at) select ${sqlString(extraSessionId)}::uuid, id, 'Integration second device', 'Curl', true, false, 'integration', 'active', now(), now(), now() + interval '10 years' from stexor_account.accounts where external_id = ${sqlString(accountId)};`);
    assertStatus(await request("DELETE", `${apiBase}/account/sessions/${extraSessionId}`, { headers: authHeaders }), 200, "session revocation");
    const revokedSessionStatus = postgresOut("enterprise-postgres", "stexor_app", "postgres", `select status from stexor_account.sessions where id = ${sqlString(extraSessionId)}::uuid;`).trim();
    if (revokedSessionStatus !== "revoked") {
      fail("session revocation did not persist revoked status.");
    }
    log("Account integration tests passed.");
  } finally {
    redisDelete([
      `${redisPrefix}:otp:${signupChallengeId}`,
      `${redisPrefix}:otp-verified:${signupChallengeId}`,
      `${redisPrefix}:otp:${loginChallengeId}`,
      `${redisPrefix}:otp:${secondSignupChallengeId}`,
      `${redisPrefix}:otp-verified:${secondSignupChallengeId}`,
    ]);
    for (const id of createdAccountIds.reverse()) {
      postgres("enterprise-postgres", "stexor_app", "postgres", `delete from stexor_account.accounts where external_id = ${sqlString(id)};`, { allowFailure: true, capture: true });
    }
  }
}

function help() {
  log(`Usage: sh scripts/stexor-ops.sh <command> [--key value]

Commands:
  access-review
  account-integration-tests
  alert-evidence
  apply-postgres-migrations
  backup-mariadb
  backup-keycloak
  backup-minio
  backup-restore-drill
  backup-restore-drill-keycloak
  backup-restore-drill-mariadb
  backup-restore-drill-minio
  backup-restore-drill-secret-manager-metadata
  backup-postgres
  backup-secret-manager-metadata
  browser-e2e-tests
  certificate-expiry-check
  chaos-profile
  cloudflare-access-admin
  cloudflare-from-zero
  dependency-hygiene
  dr-readiness-check
  dr-evidence
  enterprise-check
  enterprise-hardening-audit
  enterprise-requirements-check
  enterprise-10-check
  evidence-bundle
  evidence-bundle-verify
  external-uptime-check
  failure-tests
  fault-injection-tests
  full-restore-drill
  generate-sbom
  github-actions-config
  github-actions-run-evidence
  github-branch-protection
  github-environments
  governance-check
  ha-config-check
  init-local-secrets
  infra-health
  install-mariadb-backup-cron
  install-postgres-backup-cron
  local-secret-manager
  load-profile
  load-benchmark
  load-smoke
  linux-portability-check
  maintainability-hygiene
  managed-secrets-preflight
  offsite-backup-restic
  offsite-restore-drill-restic
  performance-hygiene
  pre-go-live-evidence
  prune-postgres-backups
  production-go-no-go
  production-preflight
  repo-coverage-check
  release-evidence
  release-artifact-gate
  rollback-release
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
  supply-chain-hygiene
  testing-hygiene
  validate-local-secrets
  waf-smoke`);
}

const commands = {
  "access-review": accessReview,
  "account-integration-tests": accountIntegrationTests,
  "alert-evidence": alertEvidence,
  "apply-postgres-migrations": applyPostgresMigrations,
  "backup-keycloak": backupKeycloakConfig,
  "backup-mariadb": backupMariadb,
  "backup-minio": backupMinio,
  "backup-restore-drill": backupRestoreDrill,
  "backup-restore-drill-keycloak": backupRestoreDrillKeycloakConfig,
  "backup-restore-drill-mariadb": backupRestoreDrillMariadb,
  "backup-restore-drill-minio": backupRestoreDrillMinio,
  "backup-restore-drill-secret-manager-metadata": backupRestoreDrillSecretManagerMetadata,
  "backup-postgres": backupPostgres,
  "backup-secret-manager-metadata": backupSecretManagerMetadata,
  "browser-e2e-tests": browserE2eTests,
  "certificate-expiry-check": certificateExpiryCheck,
  "chaos-profile": chaosProfile,
  "cloudflare-access-admin": cloudflareAccessAdmin,
  "cloudflare-from-zero": cloudflareFromZero,
  "dependency-hygiene": dependencyHygiene,
  "dr-readiness-check": drReadinessCheck,
  "dr-evidence": drEvidence,
  "enterprise-check": enterpriseCheck,
  "enterprise-hardening-audit": enterpriseHardeningAudit,
  "enterprise-requirements-check": enterpriseRequirementsCheck,
  "enterprise-10-check": enterpriseTenCheck,
  "evidence-bundle": evidenceBundle,
  "evidence-bundle-verify": evidenceBundleVerify,
  "external-uptime-check": externalUptimeCheck,
  "failure-tests": failureTests,
  "fault-injection-tests": faultInjectionTests,
  "full-restore-drill": fullRestoreDrill,
  "generate-sbom": generateSbom,
  "github-actions-config": githubActionsConfig,
  "github-actions-run-evidence": githubActionsRunEvidence,
  "github-branch-protection": githubBranchProtection,
  "github-environments": githubEnvironments,
  "governance-check": governanceCheck,
  "ha-config-check": haConfigCheck,
  "init-local-secrets": initLocalSecrets,
  "infra-health": infraHealth,
  "install-mariadb-backup-cron": installMariadbBackupCron,
  "install-postgres-backup-cron": installPostgresBackupCron,
  "local-secret-manager": localSecretManager,
  "load-profile": loadProfile,
  "load-benchmark": loadBenchmark,
  "load-smoke": loadSmoke,
  "linux-portability-check": linuxPortabilityCheck,
  "maintainability-hygiene": maintainabilityHygiene,
  "managed-secrets-preflight": managedSecretsPreflight,
  "offsite-backup-restic": offsiteBackupRestic,
  "offsite-restore-drill-restic": offsiteRestoreDrillRestic,
  "performance-hygiene": performanceHygiene,
  "pre-go-live-evidence": preGoLiveEvidence,
  "prune-postgres-backups": prunePostgresBackups,
  "production-go-no-go": productionGoNoGo,
  "production-preflight": productionPreflight,
  "repo-coverage-check": repoCoverageCheck,
  "release-evidence": releaseEvidence,
  "release-artifact-gate": releaseArtifactGate,
  "rollback-release": rollbackRelease,
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
  "supply-chain-hygiene": supplyChainHygiene,
  "testing-hygiene": testingHygiene,
  "validate-local-secrets": validateLocalSecrets,
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
