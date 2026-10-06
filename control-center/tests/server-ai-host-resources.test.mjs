import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createMachineAiManager, normalizeMachineHostResources } from '../ai/machines.mjs';
import { renderServerAi } from '../ai/ui.mjs';

const machineId = 'a'.repeat(64);

test('normalizes host resources without manufacturing values for missing metrics', () => {
  const missing = normalizeMachineHostResources({ available: false });
  assert.equal(missing.cpu.available, false);
  assert.equal(missing.memory.available, false);
  assert.equal(missing.disk.available, false);

  const partial = normalizeMachineHostResources({
    available: true,
    cpu: { available: true, usedPercent: null, cores: 4 },
    memory: { available: true, totalBytes: 1024, availableBytes: null },
    disk: { available: true, totalBytes: 4096, availableBytes: null },
  });
  assert.equal(partial.cpu.available, false, 'a missing CPU query must not become 0%');
  assert.equal(partial.memory.available, false, 'a missing RAM query must not become 0 bytes free');
  assert.equal(partial.disk.available, false, 'a missing disk query must not become 0 bytes free');

  const normalized = normalizeMachineHostResources({
    available: true,
    capturedAt: '2026-10-06T10:00:00.000Z',
    cpu: { available: true, usedPercent: 0, cores: 4 },
    memory: { available: true, totalBytes: 1024, availableBytes: 1024 },
    disk: { available: true, totalBytes: 4096, availableBytes: 2048 },
  });
  assert.equal(normalized.cpu.usedPercent, 0);
  assert.equal(normalized.memory.usedPercent, 0);
  assert.equal(normalized.disk.usedPercent, 50);
  assert.equal(normalized.capturedAt, '2026-10-06T10:00:00.000Z');
});

test('machine status returns host metrics while Server AI is disabled', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'server-ai-host-metrics-'));
  try {
    const manager = createMachineAiManager({
      stateFile: path.join(directory, 'projects.json'),
      machines: [{ id: machineId, label: 'VPS', local: true, configured: false }],
      getHostResources: async () => ({
        available: true,
        cpu: { available: true, usedPercent: 18.5, cores: 4 },
        memory: { available: true, totalBytes: 16_000, availableBytes: 4_000 },
        disk: { available: true, totalBytes: 200_000, availableBytes: 100_000 },
      }),
    });
    const status = await manager.status(machineId, { fresh: true });
    assert.equal(status.enabled, false);
    assert.equal(status.hostResources.cpu.usedPercent, 18.5);
    assert.equal(status.hostResources.memory.usedPercent, 75);
    assert.equal(status.hostResources.disk.usedPercent, 50);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('Server AI panel includes a dedicated host resource summary', () => {
  const html = renderServerAi();
  for (const key of ['cpu', 'memory', 'disk']) assert.match(html, new RegExp(`data-ai-host-${key}`));
  assert.match(html, /Metriche host non disponibili/);
});
