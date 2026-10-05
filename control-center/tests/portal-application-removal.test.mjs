import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizesPortalApplicationRemoval, createPortalApplicationRemoval } from '../ai/portal-application-removal.mjs';
import { resolveAuthorizationCapability } from '../auth/route-capabilities.mjs';

const machineId = 'a'.repeat(64);
const target = { slug: 'demo-application', name: 'Demo Application' };
const alpha = { slug: 'alpha', name: 'Alpha' };
const beta = { slug: 'beta', name: 'Beta' };

function fixture({ projects = [target], authorized = true, verified = true } = {}) {
  const calls = [];
  const remove = createPortalApplicationRemoval({
    machineId,
    authorize: async scope => { calls.push(['authorize', scope]); return authorized; },
    getContext: async () => ({ projects }),
    applyDelete: (id, payload) => { calls.push(['delete', id, payload.confirm]); return { id: 'operation-1' }; },
    invalidate: async () => { calls.push(['invalidate']); },
    verify: async id => { calls.push(['verify', id]); return verified; },
  });
  const context = { projectScope: 'machine', projectId: null, machineId, role: 'owner', subject: 'owner', sessionTokenHash: 'b'.repeat(64), latestUserMessage: 'Rimuovi app Demo Application dalla lista' };
  return { remove, context, calls };
}

test('visible label and slug authorize exactly one current target', () => {
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi app Demo Application dalla lista', target, [target]), true);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi app demo-application dalla lista', target, [target]), true);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi dalla lista Applicazioni Demo Application; conserva hosting e dati.', target, [target]), true);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi app alpha dalla lista; beta resta visibile', beta, [alpha, beta]), false);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi app alpha e beta dalla lista', alpha, [alpha, beta]), false);
  assert.equal(authorizesPortalApplicationRemoval('Non rimuovere app alpha', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('> Rimuovi app alpha', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Spiega come rimuovere app alpha', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Come posso eliminare app alpha?', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Il log dice "rimuovi app alpha"', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('"Rimuovi app alpha"', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi app alpha?', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi app alpha; non eliminare beta', alpha, [alpha, beta]), false);
  assert.equal(authorizesPortalApplicationRemoval("Puoi spiegarmi come eliminare l'app alpha?", alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Il log: rimuovi app alpha', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval("Ho scritto 'rimuovi app alpha'", alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi app beta, alpha resta', beta, [alpha, beta]), false);
  assert.equal(authorizesPortalApplicationRemoval('Rimuovi alpha e beta', alpha, [alpha, beta]), false);
  assert.equal(authorizesPortalApplicationRemoval('`Rimuovi app alpha`', alpha, [alpha]), false);
  assert.equal(authorizesPortalApplicationRemoval('Hai rimosso alpha?', alpha, [alpha]), false);
});

test('owner with fresh session removes exact label once and invalidates catalog', async () => {
  const { remove, context, calls } = fixture();
  const result = await remove({ application: target.name }, context);
  assert.equal(result.projectId, target.slug);
  assert.deepEqual(calls.map(call => call[0]), ['authorize', 'delete', 'invalidate', 'verify']);
  assert.deepEqual(calls[1], ['delete', target.slug, `REMOVE-FROM-LIST:${target.slug}`]);
});

test('post-write verification failure reports reconciliation without retry', async () => {
  const item = fixture({ verified: false });
  const result = await item.remove({ application: target.name }, item.context);
  assert.equal(result.removedFromPortal, false);
  assert.equal(result.status, 'reconciliation_required');
  assert.equal(item.calls.filter(call => call[0] === 'delete').length, 1);
});

test('stale session, viewer, continuation and ambiguous target never mutate', async () => {
  const stale = fixture({ authorized: false });
  await assert.rejects(stale.remove({ application: target.name }, stale.context), /passkey/);
  assert.deepEqual(stale.calls.map(call => call[0]), ['authorize']);
  const viewer = fixture(); viewer.context.role = 'viewer';
  await assert.rejects(viewer.remove({ application: target.name }, viewer.context));
  assert.equal(viewer.calls.length, 0);
  const continuation = fixture(); continuation.context.automaticContinuation = true;
  await assert.rejects(continuation.remove({ application: target.name }, continuation.context));
  assert.equal(continuation.calls.length, 0);
  const absent = fixture({ projects: [] });
  await assert.rejects(absent.remove({ application: target.name }, absent.context), /assente o ambigua/);
  assert.equal(absent.calls.length, 0);
  const ambiguous = fixture({ projects: [target, { slug: 'another', name: target.name }] });
  await assert.rejects(ambiguous.remove({ application: target.name }, ambiguous.context), /assente o ambigua/);
  assert.equal(ambiguous.calls.length, 0);
});

test('portal removal routes require fresh owner session', () => {
  for (const path of ['/actions/project-remove-from-list', '/control/projects/alpha/list/remove']) {
    const route = resolveAuthorizationCapability('POST', path);
    assert.equal(route.capability, 'owner:fresh');
  }
});
