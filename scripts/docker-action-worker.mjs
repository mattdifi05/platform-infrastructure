#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const BACKUP_ROOT = "/data/backups";
const KEEP_COMPLETE_MANIFESTS = 42;
const MAX_MANIFESTS = 10_000;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

function backupPrunePlan() {
  validateLiveBackupMount();
  const root = canonicalDirectory(BACKUP_ROOT);
  const manifestRoot = canonicalDirectory(path.join(root, "manifests"));
  const names = fs.readdirSync(manifestRoot).sort();
  if (names.length > MAX_MANIFESTS) fail("manifest inventory is oversized");
  const manifests = [];
  for (const name of names) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}\.json$/.test(name) || name.includes("..")) fail("manifest filename is invalid");
    const file = path.join(manifestRoot, name);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > MAX_MANIFEST_BYTES) fail("manifest file is unsafe");
    const document = JSON.parse(fs.readFileSync(file, "utf8"));
    if (document?.schema !== "platform.backup-manifest/v1" || document?.coverage?.complete !== true
      || !/^[a-z0-9](?:[a-z0-9._:-]{0,158}[a-z0-9])?$/.test(String(document.id ?? ""))
      || !Number.isFinite(Date.parse(String(document.createdAt ?? "")))
      || document?.scope?.kind !== "platform" || document?.scope?.id !== "platform"
      || document?.signature?.algorithm !== "HMAC-SHA256"
      || !/^[a-f0-9]{64}$/.test(String(document?.signature?.digest ?? ""))
      || !/^[A-Za-z0-9_-]{43}$/.test(String(document?.signature?.value ?? ""))) {
      fail("manifest structure is not admitted");
    }
    manifests.push({ id: document.id, createdAt: document.createdAt });
  }
  manifests.sort((left, right) => right.createdAt.localeCompare(left.createdAt) || left.id.localeCompare(right.id));
  const result = {
    schema: "platform.backup-prune-plan/v1",
    mode: "plan",
    keepCompleteManifests: KEEP_COMPLETE_MANIFESTS,
    completeManifestCount: manifests.length,
    retainedManifestIds: manifests.slice(0, KEEP_COMPLETE_MANIFESTS).map(({ id }) => id),
    expiredManifestIds: manifests.slice(KEEP_COMPLETE_MANIFESTS).map(({ id }) => id),
    mutationPerformed: false,
  };
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

function validateLiveBackupMount() {
  const expectedDevice = exactInteger(process.env.PLATFORM_BACKUP_ROOT_DEVICE, "backup root device", 0);
  const expectedInode = exactInteger(process.env.PLATFORM_BACKUP_ROOT_INODE, "backup root inode", 1);
  const expectedMode = exactInteger(process.env.PLATFORM_BACKUP_ROOT_MODE, "backup root mode", 0);
  const stat = fs.lstatSync(BACKUP_ROOT);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.dev !== expectedDevice || stat.ino !== expectedInode
    || stat.uid !== 0 || stat.gid !== 0 || (stat.mode & 0o7777) !== expectedMode || (stat.mode & 0o022) !== 0) {
    fail("live backup root does not match the root-owned receipt attestation");
  }
}

function exactInteger(value, label, minimum) {
  if (!/^\d+$/.test(String(value ?? ""))) fail(`${label} is invalid`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) fail(`${label} is invalid`);
  return parsed;
}

function canonicalDirectory(directory) {
  const resolved = path.resolve(directory);
  const stat = fs.lstatSync(resolved);
  if (!stat.isDirectory() || stat.isSymbolicLink() || fs.realpathSync.native(resolved) !== resolved) fail("backup directory is unsafe");
  return resolved;
}

function fail(message) {
  throw new Error(message);
}

try {
  if (process.argv.length !== 3 || process.argv[2] !== "backup-prune-plan") fail("unsupported fixed worker action");
  backupPrunePlan();
} catch (error) {
  process.stderr.write(`${error.message ?? error}\n`);
  process.exitCode = 78;
}
