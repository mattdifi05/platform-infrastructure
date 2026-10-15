import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { loadStore, upsertVersion, VaultConflictError } from '../vault/store.mjs';
import { removeVaultItem } from '../vault/management.mjs';
import { createVaultRuntime } from '../vault/runtime.mjs';
import { renderSecretPage } from '../vault/ui.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'vault-management-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const config = { storePath: path.join(root, 'vault.json'), keyFile: path.join(root, 'key.txt') };
  await writeFile(config.keyFile, `first=${'f'.repeat(64)}\n`, { mode: 0o600 });
  const item = await upsertVersion(config, { itemId: 'app-secret', value: 'fixture-current', metadata: { label: 'Ordinary credential', kind: 'runtime' } });
  const physical = path.join(root, 'application-credential.txt');
  await writeFile(physical, 'fixture-current\n', { mode: 0o600 });
  return { config, item, physical };
}

const binding = { bindingId: 'app-binding', itemId: 'app-secret', adopted: true, appliedVersionId: 'version-one', bindingRevision: 'binding-one' };
test('bound removal detaches using reviewed revisions then deletes only ciphertext; runtime bytes remain unchanged', async t => {
  const { config, item, physical } = await fixture(t); const calls = [];
  const runtime = createVaultRuntime(async request => {
    calls.push(request);
    if (request.action === 'catalog') return { available: true, vaultRevision: item.revision, bindings: [binding] };
    assert.equal((await loadStore(config)).items['app-secret'].currentVersionId, item.versionId);
    return { operationId: 'detach-one', bindingId: request.bindingId, itemId: request.itemId, detached: true, vaultRevision: request.expectedVaultRevision, bindingRevision: 'unadopted' };
  });
  const result = await removeVaultItem({ config, runtime, runtimeConfigured: true, itemId: 'app-secret', expectedRevision: item.revision });
  assert.deepEqual(calls[1], { action: 'detach', bindingId: 'app-binding', itemId: 'app-secret', expectedVaultRevision: item.revision, expectedBindingRevision: 'binding-one', confirmation: 'DETACH:app-binding' });
  assert.equal((await loadStore(config)).items['app-secret'], undefined);
  assert.equal(await readFile(physical, 'utf8'), 'fixture-current\n');
  assert.deepEqual(result, { detachedBindings: ['app-binding'], runtimeCredentialsChanged: false, encryptedRecordRemoved: true });
});

test('unavailable catalog, refused detach, or malformed detach retains the encrypted item', async t => {
  const { config, item } = await fixture(t);
  for (const result of [null, { detached: false }, { detached: true, bindingId: 'other', itemId: 'app-secret', vaultRevision: item.revision }]) {
    const runtime = createVaultRuntime(async request => request.action === 'catalog' ? { available: true, vaultRevision: item.revision, bindings: [binding] } : result);
    await assert.rejects(removeVaultItem({ config, runtime, runtimeConfigured: true, itemId: 'app-secret', expectedRevision: item.revision }));
    assert.ok((await loadStore(config)).items['app-secret']);
  }
  await assert.rejects(removeVaultItem({ config, runtime: createVaultRuntime(), runtimeConfigured: true, itemId: 'app-secret', expectedRevision: item.revision }));
  assert.ok((await loadStore(config)).items['app-secret']);
});

test('concurrent version accepted during detach prevents deletion; stale request cannot detach', async t => {
  const { config, item } = await fixture(t); let detached = 0;
  const runtime = createVaultRuntime(async request => {
    if (request.action === 'catalog') return { available: true, vaultRevision: item.revision, bindings: [binding] };
    detached++;
    await upsertVersion(config, { itemId: 'app-secret', value: 'fixture-new', expectedRevision: item.revision });
    return { detached: true, bindingId: request.bindingId, itemId: request.itemId, vaultRevision: item.revision };
  });
  await assert.rejects(removeVaultItem({ config, runtime, runtimeConfigured: true, itemId: 'app-secret', expectedRevision: item.revision }), VaultConflictError);
  assert.equal(Object.keys((await loadStore(config)).items['app-secret'].versions).length, 2);
  await assert.rejects(removeVaultItem({ config, runtime, runtimeConfigured: true, itemId: 'app-secret', expectedRevision: item.revision }), VaultConflictError);
  assert.equal(detached, 1);
});

test('ordinary unbound record can be removed when native runtime is not configured', async t => {
  const { config, item, physical } = await fixture(t);
  const result = await removeVaultItem({ config, runtime: createVaultRuntime(), itemId: 'app-secret', expectedRevision: item.revision });
  assert.deepEqual(result.detachedBindings, []);
  assert.equal(await readFile(physical, 'utf8'), 'fixture-current\n');
});

test('management explicitly separates edit, reveal and typed removal; labels and IDs are escaped', () => {
  const html = renderSecretPage({ items: [{ id: 'app<secret', label: '<unsafe-label>', projectId: 'platform', environment: 'local', value: 'fixture-current-plaintext', sealedValue: { data: 'fixture-ciphertext' } }], revision: 'r1', runtime: { available: true, bindings: [{ bindingId: 'app', itemId: 'app<secret', label: 'App', versions: [] }] } });
  assert.match(html, /data-secret-edit/); assert.match(html, /data-vault-reveal-action/); assert.match(html, /data-secret-delete/);
  assert.match(html, /name="expectedVaultRevision" value="r1"/); assert.match(html, /name="typedConfirmation" pattern="RIMUOVI"/);
  assert.match(html, /la credenziale in uso resta al servizio/); assert.match(html, /la credenziale in uso non cambia/i);
  assert.match(html, /app&lt;secret/); assert.doesNotMatch(html, /<unsafe-label>/); assert.match(html, /data-vault-binding-link="app"/);
  assert.match(html, /data-secret-edit-form[^]*?<textarea name="newValue"[^>]*><\/textarea>/);
  assert.match(html, /data-secret-revealed hidden/);
  assert.doesNotMatch(html, /fixture-current-plaintext|fixture-ciphertext/);
});
