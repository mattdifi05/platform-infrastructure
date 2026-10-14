import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApplicationOperator, APPLICATION_OPERATOR_SOCKET } from '../hosting/application-operator.mjs';
import { createHostingLifecycle } from '../hosting/lifecycle.mjs';
import { resolveAuthorizationCapability } from '../auth/route-capabilities.mjs';
const accessApplicationId = '1e77b3cc-1889-4b8b-926c-17b9ebd1a846';
function fixture(native) {
  let state = { jobs: {} }; const events = []; const catalog = [];
  const provider = {
    getProject: id => ({ id, hostname: id.startsWith('local-') ? 'local-app.example.com' : 'app.example.com', baseDomain: 'example.com', isClone: id.startsWith('local-') }),
    planVisibility: async (p, mode) => ({ projectId: p.id, mode, revision: 'r1', confirmationRequired: `SET-VISIBILITY:${p.id}:${mode}:r1` }),
    applyVisibility: async p => { events.push(`visibility:${p.projectId}:${p.mode}`); },
    getVisibility: async p => { events.push(`read:${p.id}`); return { verified: true, effective: 'private', accessApplicationId }; },
  };
  const lifecycle = createHostingLifecycle({ provider, native, store: { read: () => ({ value: structuredClone(state) }), write: (_, value) => { state = structuredClone(value); } }, registerProject: job => catalog.push(job), audit: () => {}, now: () => 1700000000000 });
  return { lifecycle, events, catalog, state: () => state };
}
test('fixed native socket contract with real HTTP transport', async () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'hosting-http-')); const socket = path.join(directory, 'operator.sock');
  const server = createServer((req, res) => { assert.equal(req.url, '/v1/operator'); let body = ''; req.on('data', chunk => { body += chunk; }); req.on('end', () => { assert.deepEqual(JSON.parse(body), { operation: 'list' }); res.end(JSON.stringify({ apps: [] })); }); });
  await new Promise(resolve => server.listen(socket, resolve));
  try {
    // Adapter checks the production destination while redirecting only this test transport.
    const adapter = createApplicationOperator({ requestImpl: (options, callback) => { assert.equal(options.socketPath, APPLICATION_OPERATOR_SOCKET); return request({ ...options, socketPath: socket }, callback); } });
    assert.deepEqual(await adapter({ operation: 'list' }), { apps: [] });
  } finally { await new Promise(resolve => server.close(resolve)); rmSync(directory, { recursive: true }); }
});
test('durable clone gates derived hostname before native clone and verifies again before activation', async () => {
  let row; let f; const operations = [];
  const native = async body => {
    operations.push(body.operation);
    if (body.operation === 'list') return { apps: [{ id: 'app', domain: 'app.example.com', baseDomain: 'example.com' }] };
    if (body.operation === 'plan') return {};
    if (body.operation === 'clone') { assert.ok(f.events.includes('visibility:local-app:private')); row = { requestId: body.requestId, sourceId: 'app', targetId: 'local-app', status: 'staged', result: { runtime: 'php' } }; return row; }
    if (body.operation === 'status') return row;
    if (body.operation === 'activate') { assert.deepEqual(body.publication, { hostname: 'local-app.example.com', verifiedAt: 1700000000, accessApplicationId }); row = { ...row, status: 'available' }; return row; }
  };
  f = fixture(native); const job = await f.lifecycle.clone('app', { confirm: 'CLONE-PRIVATE:app' });
  for (let n = 0; n < 20 && f.state().jobs[job.requestId].status !== 'available'; n++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state().jobs[job.requestId].status, 'available'); assert.equal(f.catalog.length, 1);
  assert.ok(!f.events.includes('visibility:app:private')); assert.equal(f.events.filter(event => event === 'read:local-app').length, 2);
  assert.deepEqual(operations, ['list', 'plan', 'clone', 'status', 'activate']);
});
test('payload destination overrides and stale plans rejected before mutation', async () => {
  const f = fixture(async () => { throw Error('unexpected native call'); });
  await assert.rejects(f.lifecycle.clone('app', { confirm: 'CLONE-PRIVATE:app', hostname: 'attacker.example.com' }));
  await assert.rejects(f.lifecycle.visibility('app', { mode: 'public', expectedRevision: 'old', confirm: 'wrong' }));
  assert.deepEqual(f.events, []); assert.deepEqual(f.state(), { jobs: {} });
});
test('read methods cannot resume or mutate clone jobs', async () => {
  const f = fixture(async body => { assert.equal(body.operation, 'list'); return { apps: [] }; });
  await f.lifecycle.status('app'); await f.lifecycle.plan('app', 'public'); assert.deepEqual(f.state(), { jobs: {} }); assert.ok(f.events.every(event => event.startsWith('read:')));
});
test('hosting writes classified owner fresh and reads viewer, unknown path denied', () => {
  for (const suffix of ['visibility', 'clone', 'clone/abc/cancel']) assert.equal(resolveAuthorizationCapability('POST', `/control/projects/app/${suffix}`).capability, 'owner:fresh');
  for (const suffix of ['hosting-status', 'hosting-plan']) assert.equal(resolveAuthorizationCapability('GET', `/control/projects/app/${suffix}`).capability, 'viewer');
  assert.equal(resolveAuthorizationCapability('POST', '/control/projects/app/hosting-plan').capability, 'deny');
});
test('cancellation rejects another project before native sink', async () => {
  let called = false; const f = fixture(async () => { called = true; throw Error(); });
  await assert.rejects(f.lifecycle.cancel('other', 'missing', { confirm: 'CANCEL-CLONE:missing' }));
  assert.equal(called, false);
});
test('concurrent clone admission excludes a second request and target visibility mutation', async () => {
  let release; const waiting = new Promise(resolve => { release = resolve; }); let listCalls = 0;
  const f = fixture(async body => {
    if (body.operation === 'list') { listCalls++; await waiting; return { apps: [{ id: 'app', domain: 'app.example.com', baseDomain: 'example.com' }] }; }
    if (body.operation === 'plan') return {};
    throw Error('stop worker for test');
  });
  const first = f.lifecycle.clone('app', { confirm: 'CLONE-PRIVATE:app' });
  await assert.rejects(f.lifecycle.clone('app', { confirm: 'CLONE-PRIVATE:app' }), /in progress/);
  await assert.rejects(f.lifecycle.visibility('local-app', { mode: 'public', expectedRevision: 'r1', confirm: 'SET-VISIBILITY:local-app:public:r1' }), /in progress/);
  release(); await first; assert.equal(listCalls, 1);
});
test('cancel while native staging is in flight is durable and prevents activation', async () => {
  let release; const waiting = new Promise(resolve => { release = resolve; }); let row; let cloning; const started = new Promise(resolve => { cloning = resolve; }); let activated = false;
  const f = fixture(async body => {
    if (body.operation === 'list') return { apps: [{ id: 'app', domain: 'app.example.com', baseDomain: 'example.com' }] };
    if (body.operation === 'plan') return {};
    if (body.operation === 'clone') { cloning(); await waiting; row = { requestId: body.requestId, sourceId: 'app', targetId: 'local-app', status: 'staged', result: {} }; return row; }
    if (body.operation === 'cancel') { if (!row) throw Error('not yet admitted'); row = { ...row, status: 'cancelled' }; return row; }
    if (body.operation === 'status') return row;
    if (body.operation === 'activate') { activated = true; return row; }
  });
  const job = await f.lifecycle.clone('app', { confirm: 'CLONE-PRIVATE:app' }); await started;
  await f.lifecycle.cancel('app', job.requestId, { confirm: `CANCEL-CLONE:${job.requestId}` });
  assert.equal(f.state().jobs[job.requestId].cancelRequested, true); release();
  for (let n = 0; n < 20 && f.state().jobs[job.requestId].status !== 'cancelled'; n++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.state().jobs[job.requestId].status, 'cancelled'); assert.equal(activated, false); assert.equal(f.catalog.length, 0);
});
