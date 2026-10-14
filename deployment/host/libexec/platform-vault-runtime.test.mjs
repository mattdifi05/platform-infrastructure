import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { validateRequest, validateEnvelope, validatePolicy, validatePlan, operationAfterExit, runJob } from './platform-vault-runtime.mjs';
const policy = () => ({ schema: 'platform.vault-bindings/v1', revision: 'policy-1', bindings: [{
  id: 'binding-1', itemId: 'item-1', label: 'Fixture', project: 'platform', environment: 'private', rotation: 'configuration',
  targets: [{ path: '/srv/platform-infrastructure/fixture/password', format: 'raw-file', writeMode: 'in-place', ownerUid: 0, ownerGid: 0, mode: 0o600 }],
  consumers: [{ containerId: 'a'.repeat(64), containerName: 'fixture', path: '/run/secrets/password', format: 'raw-file', health: { kind: 'docker-health' } }],
}] });

test('request validation denies secret values, commands, paths, empty identities and missing operation references', () => {
  assert.equal(validateRequest({ action: 'catalog' }).action, 'catalog');
  assert.equal(validateRequest({ action: 'adopt', bindingId: 'binding-1', confirmation: 'ADOPT:binding-1' }).action, 'adopt');
  for (const body of [{ action: 'catalog', value: 'private' }, { action: 'apply', command: 'restart' }, { action: 'apply', path: '/etc/file' },
    { action: 'status' }, { action: 'adopt' }, { action: 'adopt', bindingId: '' }, { action: 'plan', bindingId: 'binding-1' },
    { action: 'apply', bindingId: 'binding-1', planId: '../file', confirmation: 'APPLY:../file' }]) assert.throws(() => validateRequest(body));
});

test('authenticated envelopes require exact fields, finite timestamp, bounded age and untampered HMAC', () => {
  const token = Buffer.alloc(32, 17), now = 1760000000000;
  const envelope = { body: { action: 'catalog' }, nonce: 'a'.repeat(32), timestamp: now };
  const check = value => { const raw = Buffer.from(JSON.stringify(value)); return validateEnvelope(raw, createHmac('sha256', token).update(raw).digest('hex'), token, now); };
  assert.equal(check(envelope).timestamp, now);
  for (const value of [null, [], { ...envelope, timestamp: null }, { ...envelope, timestamp: 'invalid' }, { ...envelope, timestamp: now - 60001 },
    { ...envelope, timestamp: now + 60001 }, { ...envelope, timestamp: 1e100 }, { ...envelope, extra: 'field' }, { ...envelope, nonce: '../file' }]) assert.throws(() => check(value));
  const raw = Buffer.from(JSON.stringify(envelope));
  assert.throws(() => validateEnvelope(raw, 'b'.repeat(64), token, now), /unauthorized/);
  assert.throws(() => validateEnvelope(Buffer.alloc(8193), 'b'.repeat(64), token, now), /invalid-envelope/);
});

test('policy validation rejects custody, traversal, duplicate targets/items and unsupported format/mode/health', () => {
  assert.equal(validatePolicy(policy()).bindings.length, 1);
  const mutations = [
    p => { p.bindings[0].id = undefined; }, p => { p.revision = undefined; },
    p => { p.bindings[0].targets[0].path = '/srv/platform-infrastructure/../other/token'; },
    p => { p.bindings[0].targets[0].path = '/srv/platform-infrastructure/secrets/backup_signing_keys.txt'; },
    p => { p.bindings[0].targets[0].writeMode = 'replace-arbitrary'; }, p => { p.bindings[0].targets[0].mode = 0o666; },
    p => { p.bindings[0].targets[0].format = 'shell'; }, p => { p.bindings[0].targets.push(p.bindings[0].targets[0]); },
    p => { p.bindings.push({ ...structuredClone(p.bindings[0]), id: 'different' }); },
    p => { p.bindings[0].consumers[0].path = '/run/secrets/../../etc/passwd'; },
    p => { p.bindings[0].consumers[0].health = undefined; },
    p => { p.bindings[0].consumers[0].health = { kind: 'http', host: 'host\r\nHeader:value', port: 80, path: '/', expectedStatus: 200 }; },
    p => { p.bindings[0].targets[0].ancestorMetadata = [{ path: '/srv/platform-infrastructure', uid: 1000, gid: 1000, mode: 0o777 }]; },
  ];
  for (const mutate of mutations) { const candidate = policy(); mutate(candidate); assert.throws(() => validatePolicy(candidate)); }
});

test('container-env policy is admitted only for matching env-key targets and unchanged coupled-service delivery', () => {
  const p = policy(), binding = p.bindings[0]; binding.rotation = 'coupled-service';
  binding.targets[0] = { ...binding.targets[0], path: '/srv/platform-infrastructure/fixture/private.env', format: 'env-key', key: 'DB_PASSWORD' };
  binding.consumers[0] = { ...binding.consumers[0], path: binding.targets[0].path, format: 'container-env', key: 'DB_PASSWORD', restart: false };
  assert.equal(validatePolicy(p).bindings.length, 1);
  binding.rotation = 'configuration'; assert.throws(() => validatePolicy(p), /container-environment-policy/);
  binding.rotation = 'coupled-service'; binding.consumers[0].key = 'OTHER_KEY';
  assert.throws(() => validatePolicy(p), /container-environment-policy/);
});

test('plans require matching policy, Vault and binding revisions, prior version and a valid expiry', async () => {
  const p = policy(), binding = p.bindings[0], store = { revision: 'vault-1', items: { 'item-1': { versions: { next: {} } } } };
  const state = { bindings: { 'binding-1': { revision: 'binding-revision', appliedVersionId: 'old' } } };
  const plan = { bindingId: binding.id, itemId: binding.itemId, versionId: 'next', previousVersionId: 'old', policyRevision: p.revision,
    expectedVaultRevision: store.revision, expectedBindingRevision: 'binding-revision', expiresAt: new Date(Date.now() + 30000).toISOString() };
  await validatePlan(plan, binding, p, state, store);
  for (const patch of [{ expectedVaultRevision: 'changed' }, { expectedBindingRevision: 'changed' }, { policyRevision: 'changed' },
    { itemId: 'different' }, { previousVersionId: 'different' }, { expiresAt: 'invalid' }, { expiresAt: new Date(0).toISOString() }]) await assert.rejects(validatePlan({ ...plan, ...patch }, binding, p, state, store));
});

test('child exit clears stale busy state conservatively and preserves completed receipts', () => {
  assert.equal(operationAfterExit({ phase: 'queued' }).phase, 'failed');
  for (const phase of ['applying', 'verifying', 'rolling-back']) {
    const settled = operationAfterExit({ phase, deliveryVerified: true, runtimeHealthy: true });
    assert.equal(settled.phase, 'requires-reconciliation'); assert.equal(settled.runtimeHealthy, false);
  }
  const finished = { phase: 'verified', deliveryVerified: true };
  assert.strictEqual(operationAfterExit(finished), finished);
});

function jobFixture() {
  const p = policy(), binding = p.bindings[0];
  const operation = { operationId: 'op-fixture', planId: 'plan-fixture', bindingId: binding.id, itemId: binding.itemId,
    versionId: 'next', previousVersionId: 'old', phase: 'queued', deliveryVerified: false, runtimeHealthy: false };
  let state = { bindings: { [binding.id]: { revision: 'binding-old', appliedVersionId: 'old', previousVersionId: 'older', deliveryVerified: true, runtimeHealthy: true } } };
  const store = { revision: 'vault-1', items: { [binding.itemId]: { versions: { old: {}, next: {} } } } };
  const plan = { ...operation, policyRevision: p.revision, expectedVaultRevision: store.revision, expectedBindingRevision: 'binding-old',
    expiresAt: new Date(Date.now() + 30000).toISOString(), kind: 'apply' };
  const phases = []; let locked = false, runtime = 'old', disposed = false, restarts = 0;
  const lockedCheck = () => assert.equal(locked, true, 'all writes, verification and rollback must share the store lock');
  const deps = {
    readOperation: async () => structuredClone(operation), readPlan: async () => structuredClone(plan), readPolicy: async () => p,
    readState: async () => structuredClone(state), saveState: async next => { lockedCheck(); state = structuredClone(next); },
    saveOperation: async (id, next) => { lockedCheck(); phases.push(structuredClone(next)); },
    withStoreLock: async (config, callback) => { locked = true; try { return await callback({ load: async () => store }); } finally { locked = false; } },
    decryptVersion: async (config, ref) => { lockedCheck(); return ref.versionId; },
    verify: async (binding, value) => { lockedCheck(); assert.equal(runtime, value); return { deliveryVerified: true, runtimeHealthy: true }; },
    providerProbe: async () => false,
    prepare: async (binding, value) => { lockedCheck(); return { next: value, previous: runtime }; },
    writePrepared: async prepared => { lockedCheck(); runtime = prepared.next; },
    rollbackPrepared: async prepared => { lockedCheck(); runtime = prepared.previous; },
    restart: async () => { lockedCheck(); restarts++; }, disposePrepared: () => { disposed = true; },
  };
  return { deps, binding, state: () => state, runtime: () => runtime, disposed: () => disposed, phases, restarts: () => restarts };
}

test('verified delivery promotes metadata only after runtime readback under the shared lock', async () => {
  const f = jobFixture(), result = await runJob('op-fixture', f.deps);
  assert.equal(result.phase, 'verified'); assert.equal(f.runtime(), 'next');
  assert.equal(f.state().bindings[f.binding.id].appliedVersionId, 'next');
  assert.equal(f.disposed(), true); assert.equal(f.restarts(), 1);
  assert.doesNotMatch(JSON.stringify(f.phases), /plaintext|password|value/);
});

test('receipt failure after state commit rolls files and binding metadata back together under the same lock', async () => {
  const f = jobFixture(), originalSave = f.deps.saveOperation; let failed = false;
  f.deps.saveOperation = async (id, operation) => {
    if (operation.phase === 'verified' && !failed) { failed = true; throw Error('injected receipt failure'); }
    return originalSave(id, operation);
  };
  const result = await runJob('op-fixture', f.deps);
  assert.equal(result.phase, 'rolled-back'); assert.equal(f.runtime(), 'old');
  assert.equal(f.state().bindings[f.binding.id].appliedVersionId, 'old');
  assert.equal(f.state().bindings[f.binding.id].previousVersionId, 'older');
  assert.notEqual(f.state().bindings[f.binding.id].revision, 'binding-old');
  assert.equal(f.restarts(), 2); assert.equal(f.disposed(), true);
});

test('restart failure restores prior delivery, while rollback failure denies verified status', async () => {
  const restored = jobFixture(), normalRestart = restored.deps.restart; let first = true;
  restored.deps.restart = async () => { await normalRestart(); if (first) { first = false; throw Error('injected restart failure'); } };
  const restoredResult = await runJob('op-fixture', restored.deps);
  assert.equal(restoredResult.phase, 'rolled-back'); assert.equal(restored.runtime(), 'old');
  const broken = jobFixture(); broken.deps.restart = async () => { throw Error('injected restart failure'); };
  broken.deps.rollbackPrepared = async () => { throw Error('injected rollback failure'); };
  const brokenResult = await runJob('op-fixture', broken.deps);
  assert.equal(brokenResult.phase, 'requires-reconciliation');
  assert.equal(brokenResult.deliveryVerified, false); assert.equal(brokenResult.runtimeHealthy, false);
  assert.equal(broken.state().bindings[broken.binding.id].appliedVersionId, 'old');
});

test('stale CAS plan fails before materialization or restart', async () => {
  const f = jobFixture(), original = f.deps.readPlan;
  f.deps.readPlan = async () => ({ ...await original(), expectedVaultRevision: 'stale' });
  const result = await runJob('op-fixture', f.deps);
  assert.equal(result.phase, 'failed'); assert.equal(f.runtime(), 'old');
  assert.equal(f.restarts(), 0); assert.equal(f.disposed(), false);
});
