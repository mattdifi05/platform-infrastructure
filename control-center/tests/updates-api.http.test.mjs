import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { createServer } from 'node:net';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const revision = 'a'.repeat(64), targetDigest = 'sha256:' + 'b'.repeat(64);
test('real server authorizes updates before payload/context/bridge and enforces CSRF plus fresh-owner confirmation', async t => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'runtime-updates-auth-')), state = path.join(root, 'state');
  mkdirSync(state); mkdirSync(path.join(root, 'projects'));
  writeFileSync(path.join(state, 'vault.key'), `test-v1=${'a'.repeat(64)}\n`, { mode: 0o600 });
  const keyFile = path.join(root, 'updates.key'), socketPath = path.join(root, 'u.sock');
  writeFileSync(keyFile, Buffer.alloc(32, 73), { mode: 0o600 });
  const calls = [];
  const native = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const { body } = JSON.parse(Buffer.concat(chunks)); calls.push(body);
    let value;
    if (body.action === 'catalog') value = { schema: 'runtime-updates/v1', available: true, canCheck: true, revision, checkedAt: new Date().toISOString(), components: [], operations: [] };
    else if (body.action === 'host-catalog') value = { schema: 'host-updates/v1', available: true, revision, os: { id: 'ubuntu', name: 'Ubuntu', version: '26.04' }, updateCount: 2, keptBackCount: 0, rebootRequired: true, canReboot: true, canCheck: true, canApply: true, operations: [] };
    else if (body.action === 'host-plan' || body.action === 'host-reboot-plan') value = { planId: 'host-plan', revision, expiresAt: new Date(Date.now() + 60000).toISOString(), kind: body.action === 'host-plan' ? 'host-upgrade' : 'host-reboot', packageCount: 2, steps: ['Verifica'], risks: ['Fermo temporaneo'], confirmationRequired: body.action === 'host-plan' ? 'UPDATE' : 'REBOOT' };
    else if (body.action === 'plan') value = { planId: 'plan-1', revision, componentId: 'php', expiresAt: new Date(Date.now() + 60000).toISOString(), targetVersion: '8.5.12', targetDigest, affectedServices: ['php-app'], steps: ['verify'], risks: [], confirmationRequired: 'UPDATE' };
    else if (body.action === 'operation') value = { id: body.operationId, status: 'running', stage: 'verify', completedSteps: 1, totalSteps: 2 };
    else value = { operationId: 'operation-1', status: 'queued' };
    res.writeHead(body.action === 'apply' || body.action === 'check' ? 202 : 200, { 'content-type': 'application/json' }); res.end(JSON.stringify(value));
  });
  await new Promise(resolve => native.listen(socketPath, resolve));
  const reservation = createServer(); await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
  const port = reservation.address().port; await new Promise(resolve => reservation.close(resolve));
  const base = `http://127.0.0.1:${port}`, origin = `https://127.0.0.1:${port}`;
  const sessions = ['viewer', 'admin', 'owner', 'stale-owner'].map(label => ({ label, token: `runtime-updates-token-${label}`, csrf: `runtime-updates-csrf-${label}`, role: label === 'stale-owner' ? 'owner' : label, ageSeconds: label === 'stale-owner' ? 301 : 0 }));
  const child = spawn(process.execPath, ['control-center/server.mjs'], {
    cwd: path.resolve(import.meta.dirname, '../..'),
    env: { ...process.env, NODE_ENV: 'test', CONTROL_CENTER_ENV: 'test', CONTROL_CENTER_BIND_HOST: '127.0.0.1', CONTROL_CENTER_PORT: String(port), CONTROL_CENTER_AUTH_MODE: 'app-passkey', CONTROL_CENTER_AUTH_STORE: 'memory', CONTROL_CENTER_PUBLIC_ORIGIN: origin, CONTROL_CENTER_AUTH_RP_ID: '127.0.0.1', CONTROL_CENTER_FIRST_CONFIGURATION_MODE: 'disabled', CONTROL_CENTER_FIRST_CONFIGURATION_ALLOWED_CIDRS: '127.0.0.0/8', CONTROL_CENTER_FIRST_CONFIGURATION_TRUSTED_PROXY_CIDRS: '172.16.0.0/12', CONTROL_CENTER_TEST_SESSION_FIXTURES: JSON.stringify(sessions), CONTROL_CENTER_DISCOVER_HOSTED_PROJECTS: 'false', CONTROL_CENTER_DATABASE_LIVE_APPLY: 'false', CONTROL_CENTER_HOST_EXTENSION_FILE: undefined, CONTROL_CENTER_UPDATES_SOCKET: socketPath, CONTROL_CENTER_UPDATES_KEY_FILE: keyFile, PROJECTS_ROOT: path.join(root, 'projects'), CONTROL_CENTER_REPORTS_ROOT: path.join(root, 'reports'), CONTROL_CENTER_BACKUP_ROOT: path.join(root, 'backups'), ...isolatedStateEnv(state) },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk; });
  t.after(async () => { child.kill('SIGTERM'); await new Promise(resolve => child.exitCode !== null ? resolve() : child.once('exit', resolve)); native.closeAllConnections(); await new Promise(resolve => native.close(resolve)); rmSync(root, { recursive: true, force: true }); });
  let healthy = false;
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) throw Error(`Server exited: ${stderr}`);
    try { if ((await fetch(base + '/__health')).ok) { healthy = true; break; } } catch {}
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(healthy, true, stderr);
  function request(method, route, label, payload, csrf = true) {
    const session = sessions.find(item => item.label === label), headers = { accept: 'application/json', 'content-type': 'application/json' };
    if (session) headers.cookie = `__Host-platform_cc_session=${session.token}; __Host-platform_cc_csrf=${session.csrf}`;
    if (method === 'POST' && csrf) Object.assign(headers, { origin, 'sec-fetch-site': 'same-origin', 'x-csrf-token': session?.csrf || 'invalid' });
    return fetch(base + route, { method, headers, ...(payload ? { body: JSON.stringify(payload) } : {}) });
  }
  // Invalid context proves the early update dispatcher does not inspect projects.
  writeFileSync(path.join(state, 'projects.json'), 'invalid-context-fixture');
  for (const prefix of ['/control', '/control/v1']) {
    const endpoint = prefix + '/runtime-updates';
    assert.equal((await request('GET', endpoint, null)).status, 401);
    assert.equal((await request('POST', endpoint + '/check', 'viewer', {})).status, 403);
    for (const action of ['plan', 'apply']) {
      const payload = action === 'plan' ? { revision } : { revision, planId: 'plan-1', confirmation: 'UPDATE', idempotencyKey: 'request-1' };
      for (const role of [null, 'viewer', 'admin']) assert.equal((await request('POST', endpoint + '/php/' + action, role, payload)).status, role ? 403 : 401);
      assert.equal((await request('POST', endpoint + '/php/' + action, 'stale-owner', payload)).status, 428);
      assert.equal((await request('POST', endpoint + '/php/' + action, 'owner', payload, false)).status, 403);
      for (const suffix of ['/system/' + action, '/system/reboot/' + action]) {
        for (const role of [null, 'viewer', 'admin']) assert.equal((await request('POST', endpoint + suffix, role, payload)).status, role ? 403 : 401);
        assert.equal((await request('POST', endpoint + suffix, 'stale-owner', payload)).status, 428);
        assert.equal((await request('POST', endpoint + suffix, 'owner', payload, false)).status, 403);
      }
    }
  }
  assert.equal(calls.length, 0, 'Rejected requests must not reach the native bridge');
  const viewerCatalog = await request('GET', '/control/runtime-updates', 'viewer');
  assert.equal(viewerCatalog.status, 200); assert.equal((await viewerCatalog.json()).available, true);
  assert.equal((await request('POST', '/control/v1/runtime-updates/check', 'admin', {})).status, 202);
  assert.equal((await request('POST', '/control/runtime-updates/php/plan', 'owner', { revision })).status, 200);
  const apply = await request('POST', '/control/runtime-updates/php/apply', 'owner', { revision, planId: 'plan-1', confirmation: 'UPDATE', idempotencyKey: 'request-1' });
  assert.equal(apply.status, 202); assert.deepEqual(await apply.json(), { operationId: 'operation-1', status: 'queued' });
  const job = await request('GET', '/control/v1/runtime-updates/operations/operation-1', 'viewer');
  assert.equal(job.status, 200); assert.equal((await job.json()).status, 'running');
  assert.equal((await request('GET', '/control/runtime-updates/system', 'viewer')).status, 200);
  assert.equal((await request('POST', '/control/runtime-updates/system/check', 'admin', {})).status, 202);
  assert.equal((await request('POST', '/control/runtime-updates/system/plan', 'owner', { revision })).status, 200);
  assert.equal((await request('POST', '/control/runtime-updates/system/reboot/plan', 'owner', { revision })).status, 200);
  assert.equal((await request('POST', '/control/runtime-updates/system/reboot/apply', 'owner', { revision, planId: 'host-plan', confirmation: 'REBOOT', idempotencyKey: 'reboot-1' })).status, 202);
  const beforeInvalid = calls.length;
  assert.equal((await request('POST', '/control/runtime-updates/php/apply', 'owner', { revision, planId: 'plan-1', confirmation: 'YES', idempotencyKey: 'request-2' })).status, 400);
  assert.equal(calls.length, beforeInvalid, 'Wrong confirmation must not reach native apply');
});

function isolatedStateEnv(stateRoot) {
  return {
    PROJECT_STATE_FILE: path.join(stateRoot, "projects.json"),
    PROJECT_AUDIT_FILE: path.join(stateRoot, "audit.jsonl"),
    PROJECT_OPERATIONS_FILE: path.join(stateRoot, "operations.jsonl"),
    PROJECT_APPLICATIONS_FILE: path.join(stateRoot, "applications.json"),
    PROJECT_DOMAINS_FILE: path.join(stateRoot, "domains.json"),
    PROJECT_DATABASES_FILE: path.join(stateRoot, "databases.json"),
    PROJECT_DATABASE_PRINCIPALS_FILE: path.join(stateRoot, "database-principals.json"),
    PROJECT_DATABASE_DESTRUCTIVE_OPERATIONS_FILE: path.join(stateRoot, "database-destructive-operations.json"),
    PROJECT_STORAGE_BUCKETS_FILE: path.join(stateRoot, "storage-buckets.json"),
    PROJECT_SENSITIVE_MATERIALS_FILE: path.join(stateRoot, "sensitive-materials.json"),
    PROJECT_VAULT_FILE: path.join(stateRoot, "secret-vault.json"),
    CONTROL_CENTER_VAULT_KEY_FILE: path.join(stateRoot, "vault.key"),
    CONTROL_CENTER_EXISTING_SECRETS_DIR: path.join(stateRoot, "existing-secrets"),
    PROJECT_HOSTING_JOBS_FILE: path.join(stateRoot, "hosting-jobs.json"),
    PROJECT_WORKER_JOBS_FILE: path.join(stateRoot, "worker-jobs.json"),
    PROJECT_IDENTITY_ACCESS_FILE: path.join(stateRoot, "identity-access.json"),
    PROJECT_DEPLOYMENTS_FILE: path.join(stateRoot, "deployments.jsonl"),
    PROJECT_BACKUP_RECORDS_FILE: path.join(stateRoot, "backups.jsonl"),
    PROJECT_BACKUP_JOBS_DIR: path.join(stateRoot, "backup-jobs"),
    PROJECT_RESOURCE_LIMITS_FILE: path.join(stateRoot, "resource-limits.json"),
    PROJECT_SECURITY_POLICIES_FILE: path.join(stateRoot, "security-policies.json"),
    PROJECT_ALERTS_FILE: path.join(stateRoot, "alerts.json"),
    PROJECT_NOTIFICATION_CHANNELS_FILE: path.join(stateRoot, "notification-channels.json"),
    PROJECT_PROVIDER_CONNECTIONS_FILE: path.join(stateRoot, "provider-connections.json"),
    PROJECT_SETTINGS_FILE: path.join(stateRoot, "settings.json"),
    PROJECT_WEBSPACES_FILE: path.join(stateRoot, "webspaces.json"),
    PROJECT_STATUS_RUNS_FILE: path.join(stateRoot, "status-runs.jsonl"),
    PROJECT_STATUS_RUN_EVENTS_FILE: path.join(stateRoot, "status-run-events.jsonl"),
    CONTROL_CENTER_STATUS_STEP_DELAY_MS: "0",
  };
}
