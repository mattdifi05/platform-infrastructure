import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
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
