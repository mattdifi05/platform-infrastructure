import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm, chmod, symlink } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { loadStore, upsertVersion, decryptVersion, withStoreLock, protectedImportPath, VaultStoreError, VaultConflictError } from '../vault/store.mjs';
import { parseVaultKeyring, sealVaultPlaintext } from '../vault/keyring.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vault-store-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const cfg = { storePath: path.join(root, 'vault.json'), keyFile: path.join(root, 'vault.key'), lockTimeoutMs: 200 };
  await writeFile(cfg.keyFile, `first=${'f'.repeat(64)}\n`, { mode: 0o600 });
  return cfg;
}

test('immutable versions retain old credentials and reject a stale reviewed revision', async t => {
  const cfg = await fixture(t); const empty = await loadStore(cfg);
  const first = await upsertVersion(cfg, { itemId: 'app-secret', value: 'fixture-current', metadata: { projectId: 'app' }, expectedRevision: empty.revision });
  const second = await upsertVersion(cfg, { itemId: 'app-secret', value: 'fixture-next\n', expectedRevision: first.revision });
  assert.equal(await decryptVersion(cfg, { itemId: 'app-secret', versionId: first.versionId }), 'fixture-current');
  assert.equal(await decryptVersion(cfg, { itemId: 'app-secret', versionId: second.versionId }), 'fixture-next\n');
  assert.doesNotMatch(await readFile(cfg.storePath, 'utf8'), /fixture-current|fixture-next/);
  assert.doesNotMatch(JSON.stringify(second), /sealedValue|fixture-next/);
  await assert.rejects(upsertVersion(cfg, { itemId: 'app-secret', value: 'stale', expectedRevision: first.revision }), VaultConflictError);
  await assert.rejects(withStoreLock(cfg, async tx => { const state = await tx.load(); delete state.items['app-secret'].versions[first.versionId]; return tx.save(state, { expectedRevision: state.revision }); }), /immutable/);
});

test('concurrent CC and native writers share CAS and cannot lose an accepted version', async t => {
  const cfg = await fixture(t); const before = await loadStore(cfg);
  const results = await Promise.allSettled(['one', 'two'].map(value => upsertVersion(cfg, { itemId: value, value: 'fixture-' + value, expectedRevision: before.revision })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter(result => result.status === 'rejected' && result.reason instanceof VaultConflictError).length, 1);
  assert.equal(Object.keys((await loadStore(cfg)).items).length, 1);
});

test('v2 ciphertext is preserved while native adoption adds an immutable v3 version', async t => {
  const cfg = await fixture(t); const sealed = sealVaultPlaintext('fixture-legacy', 'app-secret', parseVaultKeyring(`first=${'f'.repeat(64)}`));
  await writeFile(cfg.storePath, JSON.stringify({ version: 2, items: { 'app-secret': { id: 'app-secret', sealedValue: sealed } } }), { mode: 0o600 });
  const before = await loadStore(cfg);
  assert.equal(await decryptVersion(cfg, { itemId: 'app-secret', versionId: 'legacy-v2' }), 'fixture-legacy');
  await withStoreLock(cfg, tx => tx.upsertVersion({ itemId: 'app-secret', value: 'fixture-adopted', metadata: { kind: 'runtime' }, expectedRevision: before.revision }));
  assert.deepEqual((await loadStore(cfg)).items['app-secret'].versions['legacy-v2'].sealedValue, sealed);
});

test('version-bound encryption rejects swapped ciphertext and unsafe key/store files fail closed', async t => {
  const cfg = await fixture(t);
  const first = await upsertVersion(cfg, { itemId: 'app-secret', value: 'fixture-a' });
  const second = await upsertVersion(cfg, { itemId: 'app-secret', value: 'fixture-b' });
  const raw = JSON.parse(await readFile(cfg.storePath, 'utf8'));
  raw.items['app-secret'].versions[first.versionId].sealedValue = raw.items['app-secret'].versions[second.versionId].sealedValue;
  await writeFile(cfg.storePath, JSON.stringify(raw));
  await assert.rejects(decryptVersion(cfg, { itemId: 'app-secret', versionId: first.versionId }));
  await chmod(cfg.keyFile, 0o644);
  await assert.rejects(decryptVersion(cfg, { itemId: 'app-secret', versionId: second.versionId }), VaultStoreError);
  await rm(cfg.storePath); await symlink(cfg.keyFile, cfg.storePath);
  await assert.rejects(loadStore(cfg), VaultStoreError);
});

test('protected custody files are excluded before import can read or fingerprint them', () => {
  for (const name of ['backup_signing_keys.txt', 'control_center_vault_keys.txt', 'authority-public.pem', 'authority-private.pem', 'infra-secret-manager-master.key', 'infra-secret-manager-store.json', 'APNs.p8', '/etc/platform-vps-backup/profile.json']) assert.equal(protectedImportPath(name), true, name);
  assert.equal(protectedImportPath('openai_api_key.txt'), false);
  assert.equal(protectedImportPath('smtp-password.txt'), false);
});
