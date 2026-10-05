import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPortalApplicationRemoval, publicPortalRemovalError } from '../ai/portal-application-removal.mjs';

const machineId = 'a'.repeat(64);
const target = { slug: 'demo-application', name: 'Demo Application' };

test('passkey form action is accepted by the submit handler', () => {
  const script = readFileSync(new URL('../styles/control-center.js', import.meta.url), 'utf8');
  const allowed = script.match(/var allowedActions = new Set\((\[[^\]]+\])\);/);
  assert.ok(allowed, 'submitPasskeyForm allowlist missing');
  assert.ok(JSON.parse(allowed[1]).includes('/actions/project-remove-from-list'));
  assert.match(script, /if \(!action \|\| !allowedActions\.has\(action\.pathname\)\) return false/);
});

test('stale passkey produces a safe specific tool error without mutation', async () => {
  const service = readFileSync(new URL('../ai/service.mjs', import.meta.url), 'utf8');
  assert.match(service, /name === "removePortalApplication"[\s\S]*publicPortalRemovalError\(error\)/);
  let mutations = 0;
  const remove = createPortalApplicationRemoval({
    machineId,
    authorize: async () => false,
    getContext: async () => ({ projects: [target] }),
    applyDelete: () => { mutations += 1; },
    invalidate: async () => { mutations += 1; },
    verify: async () => true,
  });
  const scope = { projectScope: 'machine', projectId: null, machineId, role: 'owner', subject: 'owner', sessionTokenHash: 'b'.repeat(64), latestUserMessage: 'Rimuovi dalla lista Applicazioni Demo Application; conserva hosting e dati.' };
  await assert.rejects(remove({ application: target.name }, scope), error => {
    assert.equal(error.code, 'PORTAL_APPLICATION_REAUTH_REQUIRED');
    assert.deepEqual(publicPortalRemovalError(error), {
      available: false,
      error: 'PORTAL_APPLICATION_REAUTH_REQUIRED',
      message: 'Riautenticati con la passkey e ripeti la richiesta: serve una sessione proprietario recente.',
      mutationPerformed: false,
    });
    return true;
  });
  assert.equal(mutations, 0);
  assert.equal(publicPortalRemovalError(new Error('private detail')), null);
});
