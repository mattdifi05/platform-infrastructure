import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHmac } from 'node:crypto';
import { createRuntimeUpdatesClient, RuntimeUpdatesError, validateRuntimeUpdatesRequest } from '../updates/client.mjs';
import { handleRuntimeUpdatesApi } from '../updates/api.mjs';
import { resolveAuthorizationCapability } from '../auth/route-capabilities.mjs';

const revision = 'a'.repeat(64), imageDigest = 'sha256:' + 'b'.repeat(64);
const plan = { planId: 'plan-1', revision, expiresAt: new Date(Date.now() + 60000).toISOString(), componentId: 'php', targetVersion: '8.5.12', targetDigest: imageDigest, affectedServices: ['php-app'], steps: ['preflight', 'apply', 'verify'], risks: ['Riavvio del runtime'], confirmationRequired: 'UPDATE' };
function catalog() {
  return { schema: 'runtime-updates/v1', revision, checkedAt: new Date().toISOString(), available: true, canCheck: true,
    components: [{ id: 'php', label: 'PHP', category: 'runtime', current: { version: '8.5.11', imageDigest, verifiedAt: new Date().toISOString() }, latestStable: { version: '9.0.0', imageDigest, sourceUrl: 'https://www.php.net/releases/' }, candidateRelease: { version: '8.5.12', imageDigest, sourceUrl: 'https://www.php.net/releases/' }, status: 'update_available', canUpdate: true, blockedReason: null, services: ['php-app'], installed: true }], operations: [] };
}
async function fixture(t, handler, options = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'updates-api-'));
  const socketPath = path.join(dir, 'u.sock'), keyFile = path.join(dir, 'key');
  const key = Buffer.alloc(32, 37); writeFileSync(keyFile, key, { mode: 0o600 });
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks), envelope = JSON.parse(raw);
    requests.push({ req, raw, envelope });
    assert.equal(req.method, 'POST'); assert.equal(req.url, '/v1/updates');
    assert.equal(req.headers['x-platform-signature'], createHmac('sha256', key).update(raw).digest('hex'));
    assert.match(envelope.nonce, /^[a-f0-9]{32}$/); assert.ok(Math.abs(Date.now() - envelope.timestamp) < 5000);
    handler(envelope.body, res);
  });
  await new Promise(resolve => server.listen(socketPath, resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); rmSync(dir, { recursive: true, force: true }); });
  return { client: createRuntimeUpdatesClient({ env: { CONTROL_CENTER_UPDATES_SOCKET: socketPath, CONTROL_CENTER_UPDATES_KEY_FILE: keyFile }, ...options }), requests };
}
const send = (res, value, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };

test('Unix client signs exact envelopes with unique nonces and retains compatible candidate separately from latest stable', async t => {
  const { client, requests } = await fixture(t, (body, res) => send(res, body.action === 'catalog' ? { ...catalog(), rawEnv: 'NEVER_RETURN_THIS', secret: 'PRIVATE' } : plan));
  const actual = await client.catalog();
  assert.equal(actual.available, true); assert.equal(actual.components[0].candidateRelease.version, '8.5.12'); assert.equal(actual.components[0].latestStable.version, '9.0.0');
  assert.equal(JSON.stringify(actual).includes('NEVER_RETURN_THIS'), false);
  assert.deepEqual(await client.plan('php', { revision }), plan);
  assert.notEqual(requests[0].envelope.nonce, requests[1].envelope.nonce);
  assert.deepEqual(requests[1].envelope.body, { action: 'plan', componentId: 'php', revision });
});

test('catalog never enables updates for absent components or unavailable native inventory', async t => {
  const source = catalog(); source.components[0].installed = false;
  const { client } = await fixture(t, (_body, res) => send(res, source));
  let result = await client.catalog();
  assert.equal(result.components[0].installed, false); assert.equal(result.components[0].canUpdate, false);
  source.available = false; source.components[0].installed = true;
  result = await client.catalog();
  assert.equal(result.canCheck, false); assert.equal(result.components[0].canUpdate, false);
});

test('missing bridge returns explicitly unavailable catalog while action rejects with 503', async () => {
  const client = createRuntimeUpdatesClient({ env: { CONTROL_CENTER_UPDATES_SOCKET: '/nonexistent-updates-fixture/u.sock', CONTROL_CENTER_UPDATES_KEY_FILE: '/nonexistent-updates-fixture/key' } });
  assert.deepEqual(await client.catalog(), { schema: 'runtime-updates/v1', revision: null, checkedAt: null, available: false, canCheck: false, canApply: false, components: [], operations: [] });
  await assert.rejects(client.check(), error => error.status === 503);
});

test('recovery gates and terminal idempotent replies survive the public metadata projection', async t => {
  const source = catalog(); source.canApply = false;
  source.operations = [{ id: 'operation-1', status: 'interrupted', stage: 'Recovery required', completedSteps: 2, totalSteps: 5, recoveryRequired: true }];
  let actionStatus = 'rolled-back';
  const { client } = await fixture(t, (body, res) => send(res, body.action === 'catalog' ? source : { operationId: 'operation-1', status: actionStatus }));
  const result = await client.catalog();
  assert.equal(result.canApply, false); assert.equal(result.components[0].canUpdate, false);
  assert.equal(result.operations[0].recoveryRequired, true);
  assert.match(result.components[0].blockedReason, /manutenzione interrotta/);
  const request = { revision, planId: 'plan-1', confirmation: 'UPDATE', idempotencyKey: 'same-request' };
  for (actionStatus of ['rolled-back', 'interrupted', 'succeeded']) assert.equal((await client.apply('php', request)).status, actionStatus);
});

test('unknown fields, paths, URL IDs and incomplete apply reject before native transport', () => {
  const invalid = [
    { action: 'shell', command: 'id' }, { action: 'check', url: 'https://example.test' },
    { action: 'plan', componentId: '../php', revision }, { action: 'operation', operationId: 'https://example.test' },
    { action: 'plan', componentId: 'php', revision: '' }, { action: 'apply', componentId: 'php', revision, planId: 'plan-1', confirmation: 'UPDATE' },
    { action: 'apply', componentId: 'php', revision, planId: 'plan-1', confirmation: 'YES', idempotencyKey: 'key-1' },
  ];
  for (const body of invalid) assert.throws(() => validateRuntimeUpdatesRequest(body), error => error.status === 400);
});

test('native stale-plan/status errors preserve actionable statuses and redact arbitrary messages', async t => {
  let status = 409;
  const { client } = await fixture(t, (_body, res) => send(res, { error: { status, code: 'stale_revision', message: 'password=SECRET /etc/private' } }, status));
  for (status of [409, 410, 412, 422]) await assert.rejects(client.plan('php', { revision }), error => error.status === status && error.code === 'stale_revision' && !/SECRET|private/.test(error.message));
});

test('malformed, oversized, truncated and timed-out native responses fail closed', async t => {
  const cases = [
    { response: res => res.end('{bad'), code: 'invalid_response' },
    { response: res => res.end('x'.repeat(2048)), options: { maxResponseBytes: 1024 }, code: 'response_too_large' },
    { response: res => { res.writeHead(200, { 'content-length': '500' }); res.write('{'); res.destroy(); }, code: 'updates_unavailable' },
    { response: () => {}, options: { timeoutMs: 30 }, code: 'updates_timeout', status: 504 },
  ];
  for (const item of cases) {
    const { client } = await fixture(t, (_body, res) => item.response(res), item.options);
    await assert.rejects(client.check(), error => error.code === item.code && error.status === (item.status || 503));
  }
});

test('wrong operation/plan identity and invalid catalog cannot present success', async t => {
  let result;
  const { client } = await fixture(t, (_body, res) => send(res, result));
  result = { ...plan, componentId: 'node' }; await assert.rejects(client.plan('php', { revision }), /non disponibile/);
  result = { id: 'other-operation', status: 'verified', stage: 'complete', completedSteps: 3, totalSteps: 3 }; await assert.rejects(client.operation('operation-1'), /non disponibile/);
  result = { ...catalog(), revision: '' }; assert.equal((await client.catalog()).available, false);
});

async function apiFixture(t, client, readJson) {
  const server = http.createServer(async (req, res) => { if (!await handleRuntimeUpdatesApi(req, res, new URL(req.url, 'http://fixture.test'), { client, ...(readJson ? { readJson } : {}) })) { res.writeHead(404); res.end(); } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}

test('HTTP canonical and v1 handlers bind IDs/payloads and report accepted operations without optimistic state', async t => {
  const calls = [];
  const client = {
    catalog: async () => catalog(), check: async () => ({ operationId: 'check-1', status: 'queued' }),
    plan: async (id, value) => { calls.push(['plan', id, value]); return plan; },
    apply: async (id, value) => { calls.push(['apply', id, value]); return { operationId: 'update-1', status: 'queued' }; },
    operation: async id => ({ id, status: 'running', stage: 'verify', completedSteps: 2, totalSteps: 3 }),
  };
  const base = await apiFixture(t, client);
  for (const prefix of ['/control', '/control/v1']) {
    assert.equal((await fetch(`${base}${prefix}/runtime-updates`)).status, 200);
    assert.equal((await fetch(`${base}${prefix}/runtime-updates/check`, { method: 'POST', body: '{}' })).status, 202);
    const review = await fetch(`${base}${prefix}/runtime-updates/php/plan`, { method: 'POST', body: JSON.stringify({ revision }) }); assert.equal(review.status, 200);
    const approved = { revision, planId: 'plan-1', confirmation: 'UPDATE', idempotencyKey: 'idem-1' };
    const apply = await fetch(`${base}${prefix}/runtime-updates/php/apply`, { method: 'POST', body: JSON.stringify(approved) });
    assert.equal(apply.status, 202); assert.deepEqual(await apply.json(), { operationId: 'update-1', status: 'queued' });
    assert.deepEqual(calls.at(-1), ['apply', 'php', approved]);
    const job = await (await fetch(`${base}${prefix}/runtime-updates/operations/update-1`)).json(); assert.equal(job.status, 'running'); assert.equal(job.stage, 'verify');
  }
});

test('HTTP rejects extra fields, malformed IDs/JSON, oversized input and unsupported methods without invoking native actions', async t => {
  let calls = 0; const base = await apiFixture(t, { check: () => { calls++; } });
  for (const [route, body, expected] of [
    ['/check', '{bad', 400], ['/check', '{"path":"/etc/private"}', 400],
    ['/check', JSON.stringify({ extra: 'x'.repeat(65536) }), 413], ['/php%2Fetc/plan', '{}', 400],
  ]) assert.equal((await fetch(base + '/control/runtime-updates' + route, { method: 'POST', body })).status, expected);
  assert.equal((await fetch(base + '/control/runtime-updates/check', { method: 'DELETE' })).status, 404);
  assert.equal(calls, 0);
});

test('HTTP uses injected JSON reader and never exposes unexpected native/adapter exceptions', async t => {
  let reads = 0;
  const base = await apiFixture(t, { plan: async () => { throw Error('password=SECRET'); } }, async () => { reads++; return { revision }; });
  const response = await fetch(base + '/control/runtime-updates/php/plan', { method: 'POST', body: '{}' });
  assert.equal(response.status, 503); assert.equal(reads, 1); assert.doesNotMatch(await response.text(), /SECRET|password/);
});

test('route capabilities require viewer for reads, admin for checks, fresh owner for plans/apply in both namespaces', () => {
  for (const prefix of ['/control', '/control/v1']) for (const [method, suffix, capability] of [
    ['GET', '', 'viewer'], ['POST', '/check', 'admin'], ['POST', '/php/plan', 'owner:fresh'], ['POST', '/php/apply', 'owner:fresh'], ['GET', '/operations/update-1', 'viewer'],
  ]) assert.equal(resolveAuthorizationCapability(method, prefix + '/runtime-updates' + suffix).capability, capability);
});
