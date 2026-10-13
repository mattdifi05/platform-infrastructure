import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { hostExtension, HOST_EXTENSION_FILE, validateHostExtensionPath } from '../host-extension.mjs';
import { readVpsBackupCatalog } from '../backup/vps-catalog.mjs';
import { normalizeBackupResource, createBackupJobDocument } from '../backup/contracts.mjs';

test('clean installation has no host application integrations or backup catalog', () => {
  assert.deepEqual(Object.keys(hostExtension), []);
  assert.equal(readVpsBackupCatalog(undefined), null);
  const resource = normalizeBackupResource({ kind: 'platform-state', externalId: 'runtime', projectId: 'example-app', name: 'runtime' });
  assert.equal(resource.projectId, 'platform');
  assert.throws(() => createBackupJobDocument({
    id: 'restore-example', operation: 'restore-production', scope: { kind: 'application', id: 'example-app' },
    resources: [{ kind: 'source', externalId: 'example-app', projectId: 'example-app', name: 'example-app' }],
    sourceManifestPath: 'manifests/example.json', sourceManifestDigest: 'a'.repeat(64), restoreProfileDigest: 'b'.repeat(64),
  }), /restricted/);
});

test('host extension cannot select project code or bypass the fixed path', () => {
  assert.equal(validateHostExtensionPath(HOST_EXTENSION_FILE), HOST_EXTENSION_FILE);
  for (const value of ['', '/var/www/projects/example/index.mjs', '/tmp/index.mjs', '/run/platform-host-extension/../index.mjs', 'file:///run/platform-host-extension/index.mjs']) {
    assert.throws(() => validateHostExtensionPath(value), /fixed protected/);
  }
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', `await import(${JSON.stringify(new URL('../host-extension.mjs', import.meta.url).href)})`], {
    env: { ...process.env, CONTROL_CENTER_HOST_EXTENSION_FILE: '/tmp/untrusted.mjs' }, encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /fixed protected deployment path/);
});


test('dedicated runtime naming preserves generic defaults and bounds explicit host mappings', () => {
  const source = readFileSync(new URL('../server.mjs', import.meta.url), 'utf8');
  const start = source.indexOf('function dedicatedRuntimeName(project) {');
  const end = source.indexOf('\nfunction resourceToken(', start);
  assert.ok(start >= 0 && end > start);
  const runtimeName = extension => new Function('hostExtension', `${source.slice(start, end)};return dedicatedRuntimeName;`)(extension);
  for (const [runtime, prefix] of [['static', 'static'], ['node', 'node'], ['php', 'php']]) {
    assert.equal(runtimeName({})({ runtime, slug: 'example-app' }), `${prefix}-example-app`);
  }
  const project = { runtime: 'node', slug: 'example-app' };
  assert.equal(runtimeName({ dedicatedRuntimeName: value => value === project ? 'existing-api' : undefined })(project), 'existing-api');
  assert.equal(runtimeName({ dedicatedRuntimeName: () => undefined })(project), 'node-example-app');
  for (const value of ['', '../other', '/container', 'has spaces', 'a'.repeat(129), 42]) {
    assert.throws(() => runtimeName({ dedicatedRuntimeName: () => value })(project), /invalid dedicated runtime name/);
  }
});
