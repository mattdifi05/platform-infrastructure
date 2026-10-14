/**
 * Shared CC/native Vault store. Config: {storePath, lockPath?, keyFile,
 * activeKeyId?, ownerUid?, ownerGid?, lockTimeoutMs?}. Native workers must use
 * the same underlying lock file as CC, normally `${storePath}.lock`.
 *
 * loadStore(config) -> {version:3, items, revision}; revision hashes ciphertext
 * state bytes, never key material. V2 records become immutable `legacy-v2`
 * versions without decrypting or rewriting them.
 * withStoreLock(config, async tx => ...) exposes tx.load(), tx.upsertVersion(),
 * tx.deleteItem(), tx.save(). upsertVersion(config,args) also acquires this lock.
 * args: {itemId,value,metadata?,expectedRevision?}; result contains public item,
 * versionId and new revision only. decryptVersion(config,{itemId,versionId})
 * returns plaintext for internal native use only; never log/return it to users.
 * No stale-lock stealing: an interrupted writer needs explicit reconciliation.
 */
import { constants, lstatSync, openSync, fstatSync, readFileSync, closeSync } from 'node:fs';
import { open, lstat, mkdir, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { parseVaultKeyring, sealVaultPlaintext, openVaultCiphertext } from './keyring.mjs';

export class VaultStoreError extends Error {}
export class VaultConflictError extends VaultStoreError {}
const MAX_BYTES = 16 * 1024 * 1024;
const MAX_VALUE_BYTES = 64 * 1024;
const MAX_ITEMS = 2000;
const MAX_VERSIONS = 64;
const idPattern = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,159}$/;
const metadataFields = new Set(['itemKey', 'label', 'projectId', 'environment', 'kind', 'username', 'url', 'rotationDays', 'rotationStatus', 'linkedApps', 'source', 'createdAt', 'updatedAt', 'valueStored', 'valueFingerprint', 'fingerprintStored', 'valueExposed']);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = message => { throw new VaultStoreError(message); };
const check = (condition, message) => { if (!condition) fail(message); };
const canonical = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);

function config(input) {
  check(input && typeof input.storePath === 'string' && path.isAbsolute(input.storePath), 'Vault store path is not configured');
  const result = { ownerUid: process.getuid?.() ?? 1000, ownerGid: process.getgid?.() ?? 1000, lockTimeoutMs: 5000, ...input };
  result.lockPath ||= `${result.storePath}.lock`;
  check(path.isAbsolute(result.lockPath) && path.dirname(result.lockPath) === path.dirname(result.storePath) && result.lockPath !== result.storePath, 'Vault lock must be a separate file beside the store');
  check(Number.isInteger(result.ownerUid) && Number.isInteger(result.ownerGid) && Number.isInteger(result.lockTimeoutMs) && result.lockTimeoutMs > 0 && result.lockTimeoutMs <= 30000, 'Vault store ownership or lock timeout is invalid');
  return result;
}

function safeInfo(info, cfg, key = false) {
  check(info.isFile() && info.nlink === 1 && (info.mode & 0o777) === 0o600 && (info.uid === cfg.ownerUid || key && info.uid === 0), 'Vault protected file metadata is unsafe');
}

function readProtectedSync(filename, cfg, { missing = false, key = false } = {}) {
  let descriptor;
  try {
    const before = lstatSync(filename); safeInfo(before, cfg, key);
    descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(descriptor); safeInfo(opened, cfg, key);
    check(before.dev === opened.dev && before.ino === opened.ino && opened.size <= MAX_BYTES, 'Vault file changed or exceeds its size ceiling');
    return readFileSync(descriptor);
  } catch (error) {
    if (missing && error.code === 'ENOENT') return Buffer.alloc(0);
    if (error instanceof VaultStoreError) throw error;
    fail('Vault protected file is unavailable');
  } finally { if (descriptor !== undefined) closeSync(descriptor); }
}

export function normalizeStore(value, revision = '') {
  check(value && typeof value === 'object' && !Array.isArray(value) && [2, 3].includes(Number(value.version)), 'Unsupported Vault state');
  check(value.items && typeof value.items === 'object' && !Array.isArray(value.items) && Object.keys(value.items).length <= MAX_ITEMS, 'Vault item inventory is invalid');
  const items = {};
  for (const [itemId, source] of Object.entries(value.items)) {
    check(idPattern.test(itemId) && source && typeof source === 'object' && !Array.isArray(source), 'Vault item identity is invalid');
    if (source.deletedAt) continue;
    const item = structuredClone(source);
    if (!item.versions) {
      check(item.sealedValue?.version === 2, 'Legacy Vault ciphertext requires an explicit migration');
      item.versions = { 'legacy-v2': { versionId: 'legacy-v2', createdAt: item.createdAt || item.sealedValue.createdAt || null, sealedValue: item.sealedValue } };
      item.currentVersionId = 'legacy-v2';
    }
    check(typeof item.versions === 'object' && !Array.isArray(item.versions) && Object.keys(item.versions).length > 0 && Object.keys(item.versions).length <= MAX_VERSIONS, 'Vault version inventory is invalid');
    for (const [versionId, version] of Object.entries(item.versions)) {
      check(idPattern.test(versionId) && version?.versionId === versionId && version.sealedValue?.version === 2 && version.sealedValue.alg === 'aes-256-gcm', 'Vault version ciphertext is invalid');
      const sealed = version.sealedValue;
      check(['keyId', 'iv', 'tag', 'data'].every(key => typeof sealed[key] === 'string' && sealed[key].length > 0) && sealed.data.length <= MAX_VALUE_BYTES * 2, 'Vault version ciphertext is incomplete');
    }
    check(item.versions[item.currentVersionId], 'Vault current version is absent');
    item.id = itemId; item.sealedValue = item.versions[item.currentVersionId].sealedValue;
    item.valueStored = true; items[itemId] = item;
  }
  return { version: 3, items, updatedAt: value.updatedAt || null, revision };
}

export function readStoreSync(input) {
  const cfg = config(input); const bytes = readProtectedSync(cfg.storePath, cfg, { missing: true });
  try { return normalizeStore(bytes.length ? JSON.parse(bytes.toString('utf8')) : { version: 3, items: {}, updatedAt: null }, hash(bytes)); }
  catch (error) { if (error instanceof VaultStoreError) throw error; fail('Vault state is unreadable'); }
}

export async function loadStore(input) { return readStoreSync(input); }

function keyring(cfg) {
  check(typeof cfg.keyFile === 'string' && path.isAbsolute(cfg.keyFile), 'Dedicated Vault key file is not configured');
  try { return parseVaultKeyring(readProtectedSync(cfg.keyFile, cfg, { key: true }).toString('utf8'), { activeKeyId: cfg.activeKeyId || '' }); }
  catch { fail('Dedicated Vault keyring is unavailable or invalid'); }
}

export function publicItem(item) {
  return { ...Object.fromEntries(Object.entries(item || {}).filter(([key]) => metadataFields.has(key) && !['valueFingerprint', 'fingerprintStored', 'valueExposed'].includes(key))), id: item.id, currentVersionId: item.currentVersionId, valueStored: true, valueExposed: false, versions: Object.values(item.versions).map(version => ({ versionId: version.versionId, createdAt: version.createdAt })) };
}

async function save(cfg, next, before, expectedRevision) {
  if (expectedRevision !== undefined && expectedRevision !== before.revision) throw new VaultConflictError('Vault changed; refresh before retrying');
  const normalized = normalizeStore(next);
  for (const [id, previous] of Object.entries(before.items)) {
    if (!normalized.items[id]) continue;
    for (const [versionId, version] of Object.entries(previous.versions)) {
      check(canonical(normalized.items[id].versions[versionId]) === canonical(version), 'Existing Vault versions are immutable');
    }
  }
  delete normalized.revision; normalized.updatedAt = new Date().toISOString();
  const bytes = Buffer.from(`${JSON.stringify(normalized)}\n`); check(bytes.length <= MAX_BYTES, 'Vault exceeds its storage ceiling');
  const temporary = `${cfg.storePath}.tmp-${randomUUID()}`;
  let file;
  try {
    file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    if (process.getuid?.() === 0) await file.chown(cfg.ownerUid, cfg.ownerGid);
    await file.writeFile(bytes); await file.sync(); await file.close(); file = null;
    await rename(temporary, cfg.storePath);
    const directory = await open(path.dirname(cfg.storePath), constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await directory.sync(); } finally { await directory.close(); }
    return normalizeStore(normalized, hash(bytes));
  } finally { await file?.close(); try { await unlink(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; } }
}

export async function withStoreLock(input, callback) {
  const cfg = config(input); await mkdir(path.dirname(cfg.storePath), { recursive: true, mode: 0o700 });
  const parent = await lstat(path.dirname(cfg.storePath)); check(parent.isDirectory() && !parent.isSymbolicLink(), 'Vault directory is unsafe');
  const deadline = Date.now() + cfg.lockTimeoutMs; let lock;
  while (!lock) {
    try { lock = await open(cfg.lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
    catch (error) {
      if (error.code !== 'EEXIST') fail('Vault lock is unavailable');
      try { safeInfo(await lstat(cfg.lockPath), cfg, true); } catch (inspection) { if (inspection.code === "ENOENT") continue; throw inspection; }
      if (Date.now() >= deadline) throw new VaultConflictError('Vault writer is busy; refresh before retrying');
      await new Promise(resolve => setTimeout(resolve, 25));
    }
  }
  try {
    if (process.getuid?.() === 0) await lock.chown(cfg.ownerUid, cfg.ownerGid);
    await lock.writeFile(randomUUID()); await lock.sync();
    const tx = {
      load: () => loadStore(cfg),
      save: async (next, { expectedRevision } = {}) => { const current = await loadStore(cfg); return save(cfg, next, current, expectedRevision); },
      upsertVersion: async ({ itemId, value, metadata = {}, expectedRevision } = {}) => {
        check(typeof itemId === 'string' && idPattern.test(itemId) && typeof value === 'string' && Buffer.byteLength(value) > 0 && Buffer.byteLength(value) <= MAX_VALUE_BYTES, 'Vault item or value is invalid');
        check(metadata && typeof metadata === 'object' && !Array.isArray(metadata) && Object.keys(metadata).every(key => metadataFields.has(key)), 'Vault item metadata fields are invalid');
        const current = await loadStore(cfg); const previous = current.items[itemId];
        check(!protectedVaultItem(previous) && !protectedVaultItem({ ...previous, ...metadata, id: itemId }), 'Protected custody material cannot be managed in the application Vault');
        check(!previous || Object.keys(previous.versions).length < MAX_VERSIONS, 'Vault version history is full; reconcile retained versions before adding another');
        const versionId = randomUUID(); const createdAt = new Date().toISOString();
        const sealedValue = sealVaultPlaintext(value, `${itemId}:version:${versionId}`, keyring(cfg), createdAt);
        const item = { ...previous, ...metadata, id: itemId, createdAt: previous?.createdAt || createdAt, updatedAt: createdAt, currentVersionId: versionId, sealedValue, valueStored: true, versions: { ...previous?.versions, [versionId]: { versionId, createdAt, sealedValue } } };
        const next = await save(cfg, { ...current, items: { ...current.items, [itemId]: item } }, current, expectedRevision);
        return { item: publicItem(next.items[itemId]), versionId, revision: next.revision };
      },
      deleteItem: async ({ itemId, expectedRevision } = {}) => {
        const current = await loadStore(cfg); check(current.items[itemId], 'Vault item is absent');
        check(!protectedVaultItem(current.items[itemId]), 'Protected custody material cannot be managed in the application Vault');
        const next = structuredClone(current); delete next.items[itemId];
        return save(cfg, next, current, expectedRevision);
      },
    };
    return await callback(tx);
  } finally {
    const opened = await lock.stat(); await lock.close();
    const actual = await lstat(cfg.lockPath);
    check(actual.dev === opened.dev && actual.ino === opened.ino, 'Vault lock identity changed');
    await unlink(cfg.lockPath);
  }
}

export async function upsertVersion(input, args) { return withStoreLock(input, tx => tx.upsertVersion(args)); }
export async function decryptVersion(input, { itemId, versionId } = {}) {
  const cfg = config(input); const store = await loadStore(cfg); const version = store.items[itemId]?.versions?.[versionId];
  check(version, 'Vault item version is absent');
  check(!protectedVaultItem(store.items[itemId]), 'Protected custody material cannot be revealed from the application Vault');
  const aad = versionId === 'legacy-v2' ? itemId : `${itemId}:version:${versionId}`;
  return openVaultCiphertext(version.sealedValue, aad, keyring(cfg));
}

export function protectedImportPath(filename) {
  const name = path.basename(String(filename || '')).toLowerCase();
  return /^docker_action_/.test(name) || /platform-vps-backup|admission-history/.test(String(filename || "")) || /(?:signing|authority|private|master|vault.*key|keyring|apns|admission|infra-secret-manager-store)/.test(name) || /\.(?:pem|p8|p12|pfx|key|crt|cer)$/.test(name);
}

/** Metadata-only custody exclusion; never decrypt, read or fingerprint a key. */
export function protectedVaultItem(item = {}) {
  item ||= {};
  return [item.itemKey, item.source].some(value => value && protectedImportPath(value)) || /(?:^|-)docker_action_/.test(String(item.id || ''));
}
