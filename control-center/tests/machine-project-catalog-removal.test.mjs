import test from 'node:test';
import assert from 'node:assert/strict';
import { createMachineProjectCatalog } from '../ai/machine-project-catalog.mjs';

const id = 'demo-application';
test('tombstone hides reader-attested project immediately after forced refresh', async () => {
  let hidden = [];
  const catalog = createMachineProjectCatalog({
    machineId: 'a'.repeat(64), local: true,
    reader: { projectsCatalog: async () => ({ projects: [{ id, filesAvailable: true }], nextCursor: null }) },
    getDiscoveredProjects: async () => hidden.length ? [] : [{ id, slug: id, name: 'Demo Application', filesAvailable: true, filesystemExists: true, relativePath: id }],
    getHiddenProjectIds: async () => hidden,
  });
  await catalog.refresh();
  assert.deepEqual(catalog.snapshot().map(project => project.id), [id]);
  hidden = [id];
  await catalog.refresh({ force: true });
  assert.deepEqual(catalog.snapshot(), []);
  assert.equal(catalog.resolveApplicationProjectId(id), null);
  assert.equal(catalog.diagnostics().available, true);
});
