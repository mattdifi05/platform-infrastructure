#!/usr/bin/env node
import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  copyFileSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  loadVaultKeyring,
  migrateVaultState,
  readLegacyVaultMaterial,
} from "../control-center/vault/keyring.mjs";

const args = parseArgs(process.argv.slice(2));
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");
const vaultFileValue = args["vault-file"] || process.env.PROJECT_VAULT_FILE || "";
const keyFileValue = args["key-file"] || process.env.CONTROL_CENTER_VAULT_KEY_FILE || "";
const legacyKeyFileValue = args["legacy-key-file"] || process.env.CONTROL_CENTER_VAULT_LEGACY_KEY_FILE || "";
if (!vaultFileValue) fail("Use --vault-file or PROJECT_VAULT_FILE.");
if (!keyFileValue) fail("Use --key-file or CONTROL_CENTER_VAULT_KEY_FILE.");
const vaultFile = path.resolve(vaultFileValue);
const keyFile = path.resolve(keyFileValue);
const legacyKeyFile = legacyKeyFileValue ? path.resolve(legacyKeyFileValue) : "";
const activeKeyId = args["active-key-id"] || process.env.CONTROL_CENTER_VAULT_ACTIVE_KEY_ID || "";
const apply = Boolean(args.apply);

if (!existsSync(vaultFile)) fail("Vault state file does not exist.");
if (!existsSync(keyFile)) fail("Dedicated Vault keyring file does not exist.");

const sourceText = readFileSync(vaultFile, "utf8");
let sourceState;
try {
  sourceState = JSON.parse(sourceText);
} catch {
  fail("Vault state is not valid JSON.");
}

const keyring = loadVaultKeyring({ keyFile, activeKeyId });
const migration = migrateVaultState({
  state: sourceState,
  keyring,
  legacyMaterial: readLegacyVaultMaterial(legacyKeyFile),
});

if (!apply) {
  emit({ mode: "dry-run", stateChanged: false, ...migration.report });
  process.exit(0);
}

if (args.confirm !== "REENCRYPT-CONTROL-CENTER-VAULT") {
  fail("Apply requires --confirm REENCRYPT-CONTROL-CENTER-VAULT.");
}
const backupDir = requireExternalPrivateDir(args["backup-dir"], "backup-dir");
const escrowDir = requireExternalPrivateDir(args["escrow-dir"], "escrow-dir");
if (backupDir === escrowDir) fail("backup-dir and escrow-dir must be separate directories.");
const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
const stateBackup = path.join(backupDir, `secret-vault.pre-v2.${stamp}.json`);
const keyEscrow = path.join(escrowDir, `control-center-vault-keys.${stamp}.txt`);
const legacyEscrow = existsSync(legacyKeyFile)
  ? path.join(escrowDir, `control-center-vault-legacy-key.${stamp}.txt`)
  : "";

copyPrivateVerified(vaultFile, stateBackup);
copyPrivateVerified(keyFile, keyEscrow);
if (legacyEscrow) copyPrivateVerified(legacyKeyFile, legacyEscrow);
writeAtomic(vaultFile, `${JSON.stringify(migration.state, null, 2)}\n`);

const writtenState = readFileSync(vaultFile, "utf8");
JSON.parse(writtenState);
emit({
  mode: "apply",
  stateChanged: true,
  backupVerified: hash(sourceText) === hash(readFileSync(stateBackup, "utf8")),
  escrowVerified: true,
  ...migration.report,
});

function requireExternalPrivateDir(value, label) {
  if (!value) fail(`Apply requires --${label}.`);
  const requested = path.resolve(value);
  mkdirSync(requested, { recursive: true, mode: 0o700 });
  const resolved = realpathSync(requested);
  if (resolved === repoRoot || resolved.startsWith(`${repoRoot}${path.sep}`)) {
    fail(`${label} must be outside the repository.`);
  }
  chmodSync(resolved, 0o700);
  return resolved;
}

function copyPrivateVerified(source, destination) {
  copyFileSync(source, destination, constants.COPYFILE_EXCL);
  chmodSync(destination, 0o600);
  if (hash(readFileSync(source)) !== hash(readFileSync(destination))) fail("Backup or escrow verification failed.");
}

function writeAtomic(destination, content) {
  const temporary = `${destination}.tmp-${process.pid}`;
  const fd = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(fd, content, "utf8");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(temporary, destination);
  chmodSync(destination, 0o600);
}

function hash(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseArgs(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const entry = values[index];
    if (!entry.startsWith("--")) continue;
    const key = entry.slice(2);
    if (["apply", "dry-run"].includes(key)) {
      parsed[key] = true;
      continue;
    }
    parsed[key] = values[index + 1] || "";
    index += 1;
  }
  return parsed;
}

function emit(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
