import test from 'node:test';
import assert from 'node:assert/strict';
import { createToolRegistry } from '../ai/tools.mjs';

const registry = createToolRegistry({ getContext: async () => ({}) });
const names = scope => registry.definitions('fast', scope).map(item => item.function.name);

test('removal tool is advertised only in owner machine chat and limit is respected', () => {
  for (const scope of [
    { projectScope: 'machine', role: 'viewer' },
    { projectScope: 'machine', role: 'admin' },
    { projectScope: 'public-web', role: 'owner' },
    { projectId: 'alpha', role: 'owner' },
    { role: 'owner' },
  ]) assert.equal(names(scope).includes('removePortalApplication'), false);
  const owner = names({ projectScope: 'machine', role: 'owner' });
  assert.equal(owner.includes('removePortalApplication'), true);
  assert.ok(owner.length <= 32);
});
