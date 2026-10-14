import test from 'node:test';
import assert from 'node:assert/strict';
import { createVaultRuntime, validateRuntimeRequest, renderVaultRuntime } from '../vault/runtime.mjs';

test('native delivery accepts only references and rejects path, command and value before the sink', async () => {
  let calls = 0;
  const runtime = createVaultRuntime(async () => { calls++; return {}; });
  for (const field of ['path', 'command', 'value', 'source', 'destination']) await assert.rejects(runtime.call({ action: 'apply', bindingId: 'app', planId: 'review', confirmation: 'APPLY:review', [field]: 'forbidden' }));
  assert.equal(calls, 0);
  assert.throws(() => validateRuntimeRequest({ action: 'adopt', bindingId: 'app', confirmation: 'ADOPT:other' }));
});

test('plans remain bound to item, version and both reviewed revisions; native errors cannot leak values', async () => {
  const input = { action: 'plan', bindingId: 'app', itemId: 'secret', versionId: 'v1', expectedVaultRevision: 'vault-one', expectedBindingRevision: 'policy-one' };
  const plan = { planId: 'review', bindingId: 'app', itemId: 'secret', versionId: 'v1', expectedVaultRevision: 'vault-one', expectedBindingRevision: 'policy-one', status: 'validated', confirmation: 'APPLY:review' };
  assert.deepEqual(await createVaultRuntime(async () => plan).call(input), plan);
  for (const field of ['versionId', 'expectedVaultRevision', 'expectedBindingRevision']) await assert.rejects(createVaultRuntime(async () => ({ ...plan, [field]: 'other' })).call(input));
  await assert.rejects(createVaultRuntime(async () => ({ ...plan, value: 'fixture-private' })).call(input), error => !error.message.includes('fixture-private'));
  await assert.rejects(createVaultRuntime(async () => { throw Error('fixture-private'); }).call(input), error => !error.message.includes('fixture-private'));
});

test('UI distinguishes storage, delivery, health and provider proof without treating references as delivery', () => {
  const html = renderVaultRuntime({ available: true, vaultRevision: 'one', bindings: [{ bindingId: 'db', itemId: 'secret', label: '<unsafe>', project: 'app', environment: 'production', rotation: { supported: false }, adopted: true, deliveryVerified: false, runtimeHealthy: true, providerVerified: false, versions: [] }] }, [{ id: 'secret', versions: [] }]);
  assert.match(html, /&lt;unsafe&gt;/);
  assert.match(html, /Consegna non verificata/);
  assert.match(html, /Ultima verifica applicazione riuscita/);
  assert.match(html, /Provider non verificato/);
  assert.doesNotMatch(html, /runtime\/plan/);
  assert.match(renderVaultRuntime({ available: false }), /non cambiano le credenziali in uso/);
});
